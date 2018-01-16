#!/usr/bin/env python

import os


class Util:

    @staticmethod
    def get_input(prompt):
        try:
            return raw_input(prompt)
        except NameError:
            return input(prompt)

    @staticmethod
    def pick_a_role(roles):
        while True:
            for i, role in enumerate(roles):
                print("[{:>3d}] {}".format(i + 1, role))

            prompt = 'Type the number (1 - {:d}) of the role to assume: '.format(len(roles))
            choice = Util.get_input(prompt)

            try:
                return list(roles.items())[int(choice) - 1]
            except IndexError:
                print("Invalid choice, try again.")

    @staticmethod
    def touch(file_name, mode=0o600):
        flags = os.O_CREAT | os.O_APPEND
        with os.fdopen(os.open(file_name, flags, mode)) as f:
            try:
                os.utime(file_name, None)
            finally:
                f.close()

    # This method returns the first non-None value in args. If all values are
    # None, None will be returned. If there are no arguments, None will be
    # returned.
    @staticmethod
    def coalesce(*args):
        for number, value in enumerate(args):
            if value is not None:
                return value
        return None

    @staticmethod
    def unicode_to_string_if_needed(object):
        if "unicode" in str(object.__class__):
            return object.encode('utf-8')
        else:
            return object
