import time

__apiversion__ = 1


class Trigger:
    def __init__(self):
        # dev_id -> [timestamp1, timestamp2, ...]
        self.seen_at_times = {}

    def __call__(self, dev_id=None, **kwargs):
        """Note that we can specify any subset of arguments we care about... in this case, just dev_id."""
        if dev_id not in self.seen_at_times:
            self.seen_at_times[dev_id] = [time.time()]
        else:
            self.seen_at_times[dev_id].append(time.time())

        print('{} seen at: {}'.format(dev_id, self.seen_at_times[dev_id]))
