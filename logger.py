'''
    __G__ = "(G)bd249ce4"
    logger -> main
'''

from os import path, environ
from contextlib import contextmanager

@contextmanager
def ignore_excpetion(*exceptions):
    '''
    catch excpetion
    '''
    try:
        yield
    except exceptions as error:
        #print("{} {} {}".format(datetime.utcnow(), EXCLAMATION_MARK, error))
        pass