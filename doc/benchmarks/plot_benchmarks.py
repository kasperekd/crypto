import matplotlib.pyplot as plt
import re
import os

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))

# Список файлов для сравнения
files = [
    'bignum_bench_time_karatsuba1.txt',
    'bignum_bench_time_simd1.txt',
    'bignum_bench_time_simd2.txt',
]
labels = [
    'Karatsuba',
    'SIMD (до -mavx2)',
    'SIMD (после -mavx2)',
]

results = {}
for fname, label in zip(files, labels):
    path = os.path.join(BENCH_DIR, fname)
    if not os.path.exists(path):
        continue
    with open(path) as f:
        lines = f.readlines()
    mul = {}
    for line in lines:
        m = re.match(r"mul\((\d+)\) avg: ([\d.]+) us", line)
        if m:
            mul[int(m.group(1))] = float(m.group(2))
    results[label] = mul


# baseline из CSV
import csv
baseline = {}
csv_path = os.path.join(BENCH_DIR, 'bignum_bench_time.csv')
if os.path.exists(csv_path):
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['operation'] == 'mul':
                baseline[int(row['digits'])] = float(row['avg_us'])
if baseline:
    results['Baseline (до оптимизаций)'] = baseline

sizes = sorted({size for d in results.values() for size in d})
plt.figure(figsize=(8,5))
for label, d in results.items():
    y = [d.get(size, None) for size in sizes]
    plt.plot(sizes, y, marker='o', label=label)
plt.xlabel('Digits')
plt.ylabel('Time, us (lower is better)')
plt.title('BigInt Multiplication Benchmark')
plt.legend()
plt.grid(True)
plt.xscale('log')
plt.yscale('log')
plt.tight_layout()
plt.savefig(os.path.join(BENCH_DIR, 'bignum_mul_bench_comparison.png'))
plt.show()
