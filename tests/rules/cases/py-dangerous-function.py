import ast

expr = input("expr: ")
# ruleid: py/dangerous-function
valor = eval(expr)
# ruleid: py/dangerous-function
exec("print(1)")
# ok: py/dangerous-function
seguro = ast.literal_eval("[1, 2]")
