with open('bench_acc.txt', 'r') as f:
    lines = f.readlines()

EXP_AND_TARGET_BITS = [
        (256, 256), (256, 256 + 192), (256 + 192, 256 + 192), 
        (512, 512), (512, 512 + 192), (512 + 192, 512 + 192), 
        (829, 829), (829, 829 + 192), (829 + 192, 829 + 192),
        (1086, 1086), (1086, 1086 + 192), (1086 + 192, 1086 + 192), 
    ]

FOLDING_DEGREES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

table = {}
for (exp_bits, target_bits) in EXP_AND_TARGET_BITS:
    table[(exp_bits, target_bits)] = {}
    for folding_degree in FOLDING_DEGREES:
        table[(exp_bits, target_bits)][folding_degree] = {}

        field = ""
        next_time = False
        for i in range(len(lines)):
            if 'new_vartime({})/{}'.format(folding_degree, target_bits) in lines[i]:
                field = "Instantiation"
                next_time = True
            elif 'pow({}) ct/{}/{}'.format(folding_degree, target_bits, exp_bits) in lines[i]:
                field = "Constant Time"
                next_time = True
            elif 'pow({}) rt/{}/{}'.format(folding_degree, target_bits, exp_bits) in lines[i]:
                field = "Randomized"
                next_time = True
            elif 'pow({}) vt/{}/{}'.format(folding_degree, target_bits, exp_bits) in lines[i]:
                field = "Variable Time"
                next_time = True
            elif next_time == True and 'time:' in lines[i]:     
                time = ((lines[i].split('['))[1]).split('s')[1][1:] + 's'        
                table[(exp_bits, target_bits)][folding_degree][field] = time
                next_time = False

for (exp_bits, target_bits) in EXP_AND_TARGET_BITS:
    with open('acc_{}_{}.csv'.format(exp_bits, target_bits), 'w') as f:
        f.write("Folding Degree, Instantiation + Randomized, Instantiation, Constant Time, Randomized, Variable Time\n")
        for folding_degree in FOLDING_DEGREES:
            inst_time = table[(exp_bits, target_bits)][folding_degree]['Instantiation']
            const_time = table[(exp_bits, target_bits)][folding_degree]['Constant Time']
            randomized_time = table[(exp_bits, target_bits)][folding_degree]['Randomized']
            var_time = table[(exp_bits, target_bits)][folding_degree]['Variable Time']

            if ' ns' in inst_time:
                t = float(inst_time.split(' ns')[0]) / 1000 / 1000
            if ' µs' in inst_time:
                t = float(inst_time.split(' µs')[0]) / 1000
            elif ' ms' in inst_time:
                t = float(inst_time.split(' ms')[0]) 
            elif ' s' in inst_time:
                t = float(inst_time.split(' s')[0]) * 1000

            if ' µs' in randomized_time:
                t += float(randomized_time.split(' µs')[0]) / 1000
            elif ' ms' in randomized_time:
                t += float(randomized_time.split(' ms')[0])
            elif ' s' in randomized_time:
                t += float(randomized_time.split(' s')[0]) * 1000

            f.write('{}, {:.2f} ms, {}, {}, {}, {}\n'.format(folding_degree, t, inst_time, const_time, randomized_time, var_time))