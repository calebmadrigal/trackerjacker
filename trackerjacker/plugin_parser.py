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

plugin_config is a dict of config passed to Trigger as kwargs.

Note that this plugin system is not sandboxed, so if the code in trigger_path brakes something,
the host program will break (unless it is explicitly handling any errors).

Last, a trigger can override any config parameters with the __config__ param.
"""

import ast
import json
from .common import TJException

CURRENT_TRIGGER_API_VERSION = 1


def parse_trigger_plugin(trigger_path, plugin_config, parse_only=False):
    """Parse plugin file and return the trigger config."""

    # Open and exec plugin definitions
    with open(trigger_path, 'r') as f:
        trigger_code = f.read()
    trigger_vars = {}
    exec(trigger_code, trigger_vars)

    # Get trigger data
    api_version = trigger_vars.get('__apiversion__', CURRENT_TRIGGER_API_VERSION)
    config = trigger_vars.get('__config__', {})
    trigger = trigger_vars.get('trigger', None)
    trigger_class = trigger_vars.get('Trigger', None)

    if parse_only:
        trigger = None
    else:
        if trigger_class:
            # Pass optional plugin_config to trigger class
            plugin_config = parse_plugin_config(plugin_config)

            # Instantiate class. Note that only a trigger function or class can be defined (and class takes priority)
            # Assume the class is called 'Trigger'
            try:
                trigger = trigger_class(**plugin_config)
            except Exception as e:
                raise TJException('Error loading plugin ({}): {}'.format(trigger_path, e))

        if not trigger:
            raise TJException('Plugin file must specify a "trigger" function or a "Trigger" class')

    return {'trigger': trigger, 'api_version': api_version, 'config': config}


def parse_plugin_config(plugin_config_str):
    """Attempt to parse the config as ast or json."""
    if not plugin_config_str:
        return {}

    try:
        return ast.literal_eval(plugin_config_str)
    except SyntaxError:
        pass

    try:
        return json.loads(plugin_config_str)
    except json.decoder.JSONDecodeError:
        pass

    return {}
