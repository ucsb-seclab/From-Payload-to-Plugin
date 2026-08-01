import json
import logging
from typing import Any, Dict, Optional

import redis.asyncio as aioredis

class RedisTaskSource:

    def __init__(self, host, port):
        self.redis = aioredis.Redis(host=host, port=port, encoding="utf-8", decode_responses=True)

    async def next_queue(self):
        queues = await self.redis.keys("task-queue-*")
        if not queues:
            return None
        queues.sort()
        return queues[0]

    async def pop_job(self, queue, timeout = 5):
        try:
            result = await self.redis.blpop(queue, timeout=timeout)
        except aioredis.ConnectionError as exc:
            logging.error("Redis connection error: %s", exc)
            return None
        if not result:
            return None
        _, payload = result
        try:
            job = json.loads(payload)
            job["task_queue"] = queue
            return job
        except json.JSONDecodeError as exc:
            logging.error("Failed to decode job payload from %s: %s", queue, exc)
            return None

    async def delete_queue(self, queue):
        await self.redis.delete(queue)

    async def push_complete(self, queue, payload):
        await self.redis.rpush(queue, json.dumps(payload))

    async def close(self):
        await self.redis.close()
