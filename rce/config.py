"""
This module provides functionality for parsing the device configuration file in
TOML format and returns the results.
"""

# No direct invocation of this module
if __name__ == "__main__":
    import sys
    sys.exit("This module must not be invoked directly. Invoke exploit.py instead.")

import toml
import os.path as osp
from pwn import log

def get_configs_from_file(infile="devices.toml"):
    """
    Tries to read the configuration from `infile` and returns it as a dictionary.
    On failure, an error message will be printed and `None` will be returned.

    Params:
        - `infile` - Name of the config file (default: "devices.toml")

    Returns:
        Dictionary on success, `None` otherwise
    """
    try:
        result = toml.load(infile)
        return __validate_config__(result)
    except Exception as e:
        log.failure("Failed to load configuration from file: %s" % (e,))
        return None


def _byteify(data, ignore_dicts=False):
    """
    Traverses data structures like string, list and dict and turns all instances
    of 'unicode' into real instances of string by encoding them with UTF-8.

    This is required, because TOML does only support UTF-8, but handling 'unicode'
    strings in Python 2 is a pain in the a**.

    Params:
        - `data` - The data structure to transform
        - `ignore_dicts` - If setto 'True' all instances of dicts will be transformed
                        recursively (default: False)

    Returns:
        If the data is a list, a unicode string or a dict, the same data will
        be returned with all unicode strings turned into real strings.
        If the data is neither of those types, the data will be returned
        unaltered.
    """
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [ _byteify(item, ignore_dicts=True) for item in data ]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data


def __to_integer__(hexstring):
    """
    Returns the integer representation of `hexstring` which is a string containing
    a hex number.

    Params:
        - `hexstring` - String containing hex number

    Returns:
        Integer representation of `hexstring`

    Throws:
        - ValueError if `hexstring` cannot be converted
    """
    return int(hexstring, 16)


def __validate_config__(config):
    """
    Validates the configuration `config` and returns the validated data. The
    resulting dictionary is empty if there are no elements left (all were invalid).

    Params:
        - `config` - The configuration to validate

    Returns:
        The validated configuration
    """
    if len(config) <= 0:
        log.failure("Config does not contain any data!")
        return None

    config = _byteify(config)
    for dev in config.keys():
        curr = _byteify(config[dev])
        try:
            curr["system_offset"] = __to_integer__(curr["system_offset"])
            curr["libc_leak_data"] = __to_integer__(curr["libc_leak_data"])
            curr["remote_name_offset"] = __to_integer__(curr["remote_name_offset"])
            curr["bluetooth_leak_data"] = __to_integer__(curr["bluetooth_leak_data"])
            assert isinstance(curr["libc_leak_idx"], list), "The element 'libc_leak_idx' must be a list!"
            assert isinstance(curr["bluetooth_leak_idx"], list), "The element 'bluetooth_leak_idx' must be a list!"
            assert len(curr["libc_leak_idx"]) == 2, "The element 'libc_leak_idx' must contain 2 values!"
            assert len(curr["bluetooth_leak_idx"]) == 2, "The element 'bluetooth_leak_idx' must contain 2 values!"
            assert all(isinstance(x, int) for x in curr["libc_leak_idx"]), "All elements of 'libc_leak_idx' must be integers!"
            assert all(isinstance(x, int) for x in curr["bluetooth_leak_idx"]), "All elements of 'bluetooth_leak_idx' must be integers!"
        except KeyError as e:
            log.warning("Error reading config of %s: No item %s in %s. Skipping!" % (dev, e, dev, ))
            del config[dev]
            continue
        except ValueError as e:
            log.warning("Error reading config of %s: %s. Skipping!" % (dev, e,))
            del config[dev]
            continue
        except AssertionError as e:
            log.warning("Error reading config of %s: %s. Skipping!" % (dev, e,))
            del config[dev]
            continue
        config[dev] = curr

    return config
