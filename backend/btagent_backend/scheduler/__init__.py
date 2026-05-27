"""arq-backed background scheduler for BTagent (Phase 6 foundation).

Recurring hunts and housekeeping jobs run here rather than inside the
FastAPI request loop. The worker is a separate process role
(``btagent-worker`` / ``btagent-scheduler``) built from the same image —
see :mod:`btagent_backend.scheduler.worker` for the arq ``WorkerSettings``
and :mod:`btagent_backend.scheduler.jobs` for the job functions.

The first job is the Phase 6 stale-suppression sweep (#119); subsequent
Phase 6 features (hunt-pack runs, behavioral baselines, weekly pattern
mining) register their cron jobs here.
"""
