def handle_specific(flag):
    try:
        if flag:
            raise ValueError('boom')
    except ValueError:
        return 'value'
    return 'ok'
