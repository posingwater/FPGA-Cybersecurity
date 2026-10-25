import time
import cProfile
import pstats
import io
from ml_kem_fips203 import ml_kem_keygen, ml_kem_encaps, ml_kem_decaps

ITERATIONS = 1000  # Adjust this based on your CPU speed

def benchmark_latency_and_throughput():
    print(f"--- Benchmarking ML-KEM-768 (Iterations: {ITERATIONS}) ---")
    
    # 1. Benchmark Key Generation
    start_time = time.perf_counter()
    for _ in range(ITERATIONS):
        ek, dk = ml_kem_keygen()
    keygen_time = time.perf_counter() - start_time
    
    # Generate one keypair to use for Encaps/Decaps benchmarking
    ek, dk = ml_kem_keygen()

    # 2. Benchmark Encapsulation
    start_time = time.perf_counter()
    for _ in range(ITERATIONS):
        shared_k, ct = ml_kem_encaps(ek)
    encaps_time = time.perf_counter() - start_time
    
    # Generate one ciphertext to use for Decaps benchmarking
    shared_k, ct = ml_kem_encaps(ek)

    # 3. Benchmark Decapsulation
    start_time = time.perf_counter()
    for _ in range(ITERATIONS):
        _ = ml_kem_decaps(dk, ct)
    decaps_time = time.perf_counter() - start_time

    # --- Print Statistics ---
    metrics = [
        ("KeyGen", keygen_time),
        ("Encaps", encaps_time),
        ("Decaps", decaps_time)
    ]
    
    print(f"{'Operation':<10} | {'Total Time':<12} | {'Avg Latency (ms)':<18} | {'Throughput (ops/sec)'}")
    print("-" * 67)
    for name, total_t in metrics:
        avg_ms = (total_t / ITERATIONS) * 1000
        ops_sec = ITERATIONS / total_t
        print(f"{name:<10} | {total_t:<10.4f} s | {avg_ms:<15.4f} ms | {ops_sec:<10.2f}")

def profile_bottlenecks():
    print("\n--- Profiling Function Bottlenecks (100 Iterations) ---")
    print("This shows exactly which mathematical steps consume the most CPU time.")
    
    profiler = cProfile.Profile()
    profiler.enable()
    
    # Run a smaller batch for profiling
    for _ in range(100):
        ek, dk = ml_kem_keygen()
        shared_k, ct = ml_kem_encaps(ek)
        _ = ml_kem_decaps(dk, ct)
        
    profiler.disable()
    
    # Format and print the profiling statistics
    s = io.StringIO()
    ps = pstats.Stats(profiler, stream=s).sort_stats(pstats.SortKey.CUMULATIVE)
    
    # Print the top 15 most time-consuming functions
    ps.print_stats(15)
    
    # Filter the output to clean up standard library noise
    print("Top Bottlenecks (Look for ntt, inv_ntt, hash_g, sample_ntt):")
    lines = s.getvalue().split('\n')
    for line in lines[:20]:
        print(line)

if __name__ == "__main__":
    benchmark_latency_and_throughput()
    profile_bottlenecks()