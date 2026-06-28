"""Tests del scheduler de auditorías automáticas."""
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock

import pytest

from cyberhound.core.scheduler import ScheduleEntry, Scheduler


class TestScheduleEntry:

    def test_computes_next_run(self):
        entry = ScheduleEntry(name="test", task_fn=AsyncMock(), hour=2, minute=0)
        next_run = entry.compute_next_run()
        assert next_run is not None
        # La próxima ejecución debe ser en el futuro
        from datetime import datetime
        assert datetime.fromisoformat(next_run) > datetime.now()

    def test_should_run_now_disabled(self):
        entry = ScheduleEntry(
            name="test", task_fn=AsyncMock(), hour=2, minute=0, enabled=False
        )
        assert not entry.should_run_now()

    def test_all_days_by_default(self):
        entry = ScheduleEntry(name="test", task_fn=AsyncMock(), hour=2)
        assert len(entry.days) == 7


class TestScheduler:

    @pytest.mark.asyncio
    async def test_add_entry(self):
        s = Scheduler()
        s.add(ScheduleEntry(name="test", task_fn=AsyncMock(), hour=2))
        entries = s.list_entries()
        assert len(entries) == 1
        assert entries[0]["name"] == "test"

    @pytest.mark.asyncio
    async def test_next_run_set_on_add(self):
        s = Scheduler()
        s.add(ScheduleEntry(name="test", task_fn=AsyncMock(), hour=2))
        entries = s.list_entries()
        assert entries[0]["next_run"] is not None

    @pytest.mark.asyncio
    async def test_run_now_executes_task(self):
        s = Scheduler()
        mock_fn = AsyncMock()
        s.add(ScheduleEntry(name="my_task", task_fn=mock_fn, hour=2))
        result = await s.run_now("my_task")
        assert result is True
        mock_fn.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_now_unknown_returns_false(self):
        s = Scheduler()
        result = await s.run_now("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_enable_disable(self):
        s = Scheduler()
        s.add(ScheduleEntry(name="test", task_fn=AsyncMock(), hour=2))
        assert s.list_entries()[0]["enabled"] is True
        s.enable("test", False)
        assert s.list_entries()[0]["enabled"] is False
        s.enable("test", True)
        assert s.list_entries()[0]["enabled"] is True

    @pytest.mark.asyncio
    async def test_enable_unknown_returns_false(self):
        s = Scheduler()
        result = s.enable("nonexistent", True)
        assert result is False

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        s = Scheduler()
        s.add(ScheduleEntry(name="test", task_fn=AsyncMock(), hour=2))
        await s.start()
        assert s._running is True
        assert s._task is not None
        await s.stop()
        assert s._running is False

    @pytest.mark.asyncio
    async def test_update_last_run_after_run_now(self):
        s = Scheduler()
        s.add(ScheduleEntry(name="test", task_fn=AsyncMock(), hour=2))
        assert s.list_entries()[0]["last_run"] is None
        await s.run_now("test")
        assert s.list_entries()[0]["last_run"] is not None

    @pytest.mark.asyncio
    async def test_multiple_tasks(self):
        s = Scheduler()
        results = []
        for name in ["task_a", "task_b", "task_c"]:
            async def fn(n=name):
                results.append(n)
            s.add(ScheduleEntry(name=name, task_fn=fn, hour=2))
        for name in ["task_a", "task_b", "task_c"]:
            await s.run_now(name)
        assert set(results) == {"task_a", "task_b", "task_c"}

    @pytest.mark.asyncio
    async def test_task_error_doesnt_crash_scheduler(self):
        s = Scheduler()
        async def failing_fn():
            raise RuntimeError("Error de prueba")
        s.add(ScheduleEntry(name="failing", task_fn=failing_fn, hour=2))
        # run_now propaga la excepción
        with pytest.raises(RuntimeError):
            await s.run_now("failing")
