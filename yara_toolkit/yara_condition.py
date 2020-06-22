from typing import Union, List

SEPARATORS = [' ', '\n', '\t']
YARA_VAR_SYMBOL = "$"
OPERATORS = ["==", '<', '>', "<=", ">=", "!=", '+', '-', '*', '/', '%', '\\', '&', '|', '~', "<<", ">>", '(', ')']
SINGLE_CHAR_OPERATORS = ['<', '>', '+', '-', '*', '/', '%', '\\', '&', '|', '~', '(', ')']
MULTI_CHAR_OPERATORS = ["==", "<=", ">=", "!=", "<<", ">>"]


class YaraCondition:
    def __init__(self, values: Union[str, List] = None):
        if isinstance(values, list):
            self.values = values
        elif isinstance(values, str):
            # Parse string into list with junk separators/spacing omitted.
            self.values = []
            value_str = ""
            pending = False
            inside_possible_multichar_operator = False

            def update_str(s, v):
                # Filter out junk empty entries.
                if v != '':
                    s.append(v)

                # Blank return value to be assigned to value_str.
                return ""

            for i in range(len(values)):
                c = values[i]

                if inside_possible_multichar_operator:
                    if values[i-1] + values[i] in MULTI_CHAR_OPERATORS:
                        # Update values list and (implicitly) clear value_str.
                        value_str = update_str(self.values, value_str + values[i])
                        pending = False
                        inside_possible_multichar_operator = False

                        continue

                    # Treat it as a single char operator.
                    if pending:
                        # Update values list and (implicitly) clear value_str.
                        value_str = update_str(self.values, value_str)
                        pending = False

                    inside_possible_multichar_operator = False

                if values[i] in SEPARATORS:
                    if pending:
                        # Add pending string to list
                        # Update values list and (implicitly) clear value_str.
                        value_str = update_str(self.values, value_str)
                        pending = False
                elif values[i] in [x[0] for x in MULTI_CHAR_OPERATORS]:
                    inside_possible_multichar_operator = True
                    value_str += values[i]
                    pending = True
                elif values[i] in SINGLE_CHAR_OPERATORS:
                    if pending:
                        # Add pending string to list before starting on operator string
                        # Update values list and (implicitly) clear value_str.
                        value_str = update_str(self.values, value_str)

                    # Update values list and (implicitly) clear value_str.
                    value_str = update_str(self.values, value_str + values[i])
                    pending = True
                else:
                    value_str += values[i]
                    pending = True

                if len(values)-1 == i and pending:
                    # Update values list and (implicitly) clear value_str.
                    value_str = update_str(self.values, value_str)
                    pending = False
        else:
            raise ValueError("Values must be either string or list, got '{}'!".format(type(values)))

    def __str__(self):
        return ' '.join(self.values)

    def __repr__(self):
        return "YaraCondition<('{}')>".format(self.__str__())
