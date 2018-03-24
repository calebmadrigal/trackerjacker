__apiversion__ = 1


def trigger(dev_id=None, num_bytes=None, power=None, **kwargs):
    """Note that we can specify any subset of kwargs we are interested in."""
    if num_bytes:
        msg = 'Threshold reached for {} - {} bytes'.format(dev_id, num_bytes)
    else:
        msg = 'Saw {} at power level {}'.format(dev_id, power)

    print(msg)
    with open('plugin_output_test.txt', 'a') as f:
        f.write(msg + '\n')
