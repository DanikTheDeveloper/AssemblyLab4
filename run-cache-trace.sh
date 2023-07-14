######  meaning for each cache argument  ######
#  -s <num>   Number of set index bits. i.e., number of cache sets = 2^s
#  -E <num>   Number of lines per set. i.e., associativity, number of ways
#  -b <num>   Number of block offset bits. i.e., number of bytes per block = 2^b

###### synthetic testcases to verify correctness, verbose  ######
# [34 points] Cache config: 2 sets, direct mapped, block size = 2 Bytes, LRU vs LFU
./cache -v -s 1 -E 1 -b 1 -L -t traces/input/syn1.trace > traces/out/syn1_1L.out
echo "diff ./traces/out/syn1_1L.out ./traces/ref/syn1_1L.ref"
diff ./traces/out/syn1_1L.out ./traces/ref/syn1_1L.ref
./cache -v -s 1 -E 1 -b 1 -F -t traces/input/syn1.trace > traces/out/syn1_1F.out
echo "diff ./traces/out/syn1_1F.out ./traces/ref/syn1_1F.ref"
diff ./traces/out/syn1_1F.out ./traces/ref/syn1_1F.ref

# [34 points] Cache config: 1 set (i.e., fully associative), 2-way set associative, block size = 2 Bytes, LRU vs LFU
./cache -v -s 0 -E 2 -b 1 -L -t traces/input/syn1.trace > traces/out/syn1_2L.out
echo "diff ./traces/out/syn1_2L.out ./traces/ref/syn1_2L.ref"
diff ./traces/out/syn1_2L.out ./traces/ref/syn1_2L.ref
./cache -v -s 0 -E 2 -b 1 -F -t traces/input/syn1.trace > traces/out/syn1_2F.out
echo "diff ./traces/out/syn1_2F.out ./traces/ref/syn1_2F.ref"
diff ./traces/out/syn1_2F.out ./traces/ref/syn1_2F.ref

# [22 points] Cache config: 2 sets, 2-way set associative, block size = 2 Bytes, LRU vs LFU
./cache -v -s 1 -E 2 -b 1 -L -t traces/input/syn2.trace > traces/out/syn2_L.out
echo "diff ./traces/out/syn2_L.out ./traces/ref/syn2_L.ref"
diff ./traces/out/syn2_L.out ./traces/ref/syn2_L.ref
./cache -v -s 1 -E 2 -b 1 -F -t traces/input/syn2.trace > traces/out/syn2_F.out
echo "diff ./traces/out/syn2_F.out ./traces/ref/syn2_F.ref"
diff ./traces/out/syn2_F.out ./traces/ref/syn2_F.ref

# [30 points] Cache config: 2 sets, 4-way set associative, block size = 4 Bytes, LRU vs LFU
./cache -v -s 1 -E 4 -b 2 -L -t traces/input/syn3.trace > traces/out/syn3_L.out
echo "diff ./traces/out/syn3_L.out ./traces/ref/syn3_L.ref"
diff ./traces/out/syn3_L.out ./traces/ref/syn3_L.ref
./cache -v -s 1 -E 4 -b 2 -F -t traces/input/syn3.trace > traces/out/syn3_F.out
echo "diff ./traces/out/syn3_F.out ./traces/ref/syn3_F.ref"
diff ./traces/out/syn3_F.out ./traces/ref/syn3_F.ref

# [58 points] Cache config: 2 sets, 4-way set associative, block size = 4 Bytes, LRU vs LFU
./cache -v -s 1 -E 4 -b 2 -L -t traces/input/syn4.trace > traces/out/syn4_L.out
echo "diff ./traces/out/syn4_L.out ./traces/ref/syn4_L.ref"
diff ./traces/out/syn4_L.out ./traces/ref/syn4_L.ref
./cache -v -s 1 -E 4 -b 2 -F -t traces/input/syn4.trace > traces/out/syn4_F.out
echo "diff ./traces/out/syn4_F.out ./traces/ref/syn4_F.ref"
diff ./traces/out/syn4_F.out ./traces/ref/syn4_F.ref

# [48 points] Cache config: 1 set (i.e., fully associative), 8-way set associative, block size = 8 Bytes, LRU vs LFU
./cache -v -s 0 -E 8 -b 3 -L -t traces/input/syn5.trace > traces/out/syn5_L.out
echo "diff ./traces/out/syn5_L.out ./traces/ref/syn5_L.ref"
diff ./traces/out/syn5_L.out ./traces/ref/syn5_L.ref
./cache -v -s 0 -E 8 -b 3 -F -t traces/input/syn5.trace > traces/out/syn5_F.out
echo "diff ./traces/out/syn5_F.out ./traces/ref/syn5_F.ref"
diff ./traces/out/syn5_F.out ./traces/ref/syn5_F.ref

######  real testcases to verify correctness, concise  ######
# [90 points] Cache config (64KB): 256 sets, 4-way set associative, block size = 64 Bytes, LRU vs LFU
./cache -s 8 -E 4 -b 6 -L -t ./traces/input/real1.trace > traces/out/real1_L.out
echo "diff ./traces/out/real1_L.out ./traces/ref/real1_L.ref"
diff ./traces/out/real1_L.out ./traces/ref/real1_L.ref
./cache -s 8 -E 4 -b 6 -F -t ./traces/input/real1.trace > traces/out/real1_F.out
echo "diff ./traces/out/real1_F.out ./traces/ref/real1_F.ref"
diff ./traces/out/real1_F.out ./traces/ref/real1_F.ref

# [90 points] Cache config (32KB): 128 sets, 8-way set associative, block size = 32 Bytes, LRU vs LFU
./cache -s 7 -E 8 -b 5 -L -t ./traces/input/real2.trace > traces/out/real2_L.out
echo "diff ./traces/out/real2_L.out ./traces/ref/real2_L.ref"
diff ./traces/out/real2_L.out ./traces/ref/real2_L.ref
./cache -s 7 -E 8 -b 5 -F -t ./traces/input/real2.trace > traces/out/real2_F.out
echo "diff ./traces/out/real2_F.out ./traces/ref/real2_F.ref"
diff ./traces/out/real2_F.out ./traces/ref/real2_F.ref
