#!/usr/bin/env python3
# pylint: disable=C0111, C0103, W0703, R0902, R0903, R0912, R0913, R0914, R0915, C0413, W0122

"""Handles parsing trigger plugin files and running them.

The plugin file must be a python file which contains either a function called 'trigger'
or a class called 'Trigger'. It's also recommended to specify a '__apiversion__' (which is just an int)
for backward compatibility if api changes are made in the future.

If specifying a 'trigger' function, the trigger can take the args specified by default_trigger, and should
always take a catch-all **kwargs for future compatibility.

Likewise, if specifying a 'Trigger' class, that class must define a '__call__' method, which takes
a subset of the kwargs specified by 'default_trigger', and should always contain a catch-all **kwargs
for future compatibility.

Note that this plugin system is not sandboxed, so if the code in trigger_path brakes something,
the host program will break (unless it is explicitly handling any errors).
"""

CURRENT_TRIGGER_API_VERSION = 1


def parse_trigger_plugin(trigger_path):
    """Parse plugin file and return the trigger config."""
    with open(trigger_path, 'r') as f:
        trigger_code = f.read()
    trigger_vars = {}
    exec(trigger_code, trigger_vars)

    api_version = trigger_vars.get('__apiversion__', CURRENT_TRIGGER_API_VERSION)
    trigger = trigger_vars.get('trigger', None)
    trigger_class = trigger_vars.get('Trigger', None)

    if trigger_class:
        # Instantiate class. Note that only a trigger function or class can be defined (and class takes priority)
        # Assume the class is called 'Trigger'
        trigger = trigger_class()

    if not trigger:
        raise Exception('Plugin file must specify a "trigger" function or a "Trigger" class')

    return {'trigger': trigger, 'api_version': api_version}
