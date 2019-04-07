
"""
Converts integer constants from a file constants.py to string constants, for ease of use in the program
and saves them to a file string_constants.py
You need to run it each time you change constant.py.
"""


def main():
    with open('constants.py') as consts_file, open('string_constants.py', 'w') as str_const_file:
        print('\n\n"""\nThis file generated automatically by "make_string_consts_from_int_consts.py",\n'
              'it contains string constants used in the program.\n"""\n', file=str_const_file)
        blocks_printed = 0
        for line in consts_file:
            line = line.strip()
            if line.startswith('#'):
                # comment line
                blocks_printed += 1
            elif '=' in line and blocks_printed > 2:  # General and Database consts shouldn't be changed
                parts = line.split()
                line = f"{parts[0]} = '{parts[2]}'"
            else:
                # something wrong
                pass
            print(line, file=str_const_file, )


if __name__ == '__main__':
    main()
