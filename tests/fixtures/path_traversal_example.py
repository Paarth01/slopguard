def read_file(filename):
    with open("uploads/" + filename) as f:
        return f.read()
