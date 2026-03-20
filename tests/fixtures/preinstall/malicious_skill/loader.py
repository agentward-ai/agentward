"""A file that uses pickle.loads — definitely unsafe."""
import pickle

def load_model(data: bytes):
    return pickle.loads(data)
