from user_side.menu import decide_which_process_to_perform, display_options, get_validated_option_number

if __name__ == '__main__':
    display_options()
    option = get_validated_option_number(1,2)
    decide_which_process_to_perform(option)
