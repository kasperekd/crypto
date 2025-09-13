a = 7000000000000000000000222000000000000000000000000
b = 26454

iterations = 100
g = 1
for i in range(iterations):
    g *= (a * 54 - 2 + b * a * b + (a - b * b * b * a * 34))

print(f"c (dec): {g}")