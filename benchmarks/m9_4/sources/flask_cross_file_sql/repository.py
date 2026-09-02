def find_product(name):
    return database.execute("select * from products where name = " + name)
