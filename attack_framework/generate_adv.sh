#! /bin/bash

if [ "$4" = "IM" ]; then
    im_flag=-im
else
    im_flag=--no-im
fi

if [ "$6" = "TAR" ]; then
    db_name=DB_TARGETED/DATASET
    att_flag=0
else
    db_name=DB_UNTARGETED/DATASET
    att_flag=1
fi


# EXPERIMENTS OF gcc-O0
python adv_generator_query.py -m $1 -dj /app/vol/binaries/csv_db/${db_name}/gcc_O0.csv -d /app/DB/builds/ -p /app/vol/CFGExtractor/extracted_cfgs_variants -s $im_flag -pn $2 -hpc $5 -l $3 -at $att_flag -o greedy -sp S1 -ssp 1
python adv_generator_query.py -m $1 -dj /app/vol/binaries/csv_db/${db_name}/gcc_O0.csv -d /app/DB/builds/ -p /app/vol/CFGExtractor/extracted_cfgs_variants -s $im_flag -pn $2 -hpc $5 -l $3 -at $att_flag -o greedy -sp S1 -ssp 2


# EXPERIMENTS OF gcc-O3
python adv_generator_query.py -m $1 -dj /app/vol/binaries/csv_db/${db_name}/gcc_O3.csv -d /app/DB/builds/ -p /app/vol/CFGExtractor/extracted_cfgs_variants -s $im_flag -pn $2 -hpc $5 -l $3 -at $att_flag -o greedy -sp S2 -ssp 1
python adv_generator_query.py -m $1 -dj /app/vol/binaries/csv_db/${db_name}/gcc_O3.csv -d /app/DB/builds/ -p /app/vol/CFGExtractor/extracted_cfgs_variants -s $im_flag -pn $2 -hpc $5 -l $3 -at $att_flag -o greedy -sp S2 -ssp 2


# EXPERIMENTS OF clang-O0
python adv_generator_query.py -m $1 -dj /app/vol/binaries/csv_db/${db_name}/clang_O0.csv -d /app/DB/builds/ -p /app/vol/CFGExtractor/extracted_cfgs_variants -s $im_flag -pn $2 -hpc $5 -l $3 -at $att_flag -o greedy -sp S3 -ssp 1
python adv_generator_query.py -m $1 -dj /app/vol/binaries/csv_db/${db_name}/clang_O0.csv -d /app/DB/builds/ -p /app/vol/CFGExtractor/extracted_cfgs_variants -s $im_flag -pn $2 -hpc $5 -l $3 -at $att_flag -o greedy -sp S3 -ssp 2


# EXPERIMENTS OF clang-O3
python adv_generator_query.py -m $1 -dj /app/vol/binaries/csv_db/${db_name}/clang_O3.csv -d /app/DB/builds/ -p /app/vol/CFGExtractor/extracted_cfgs_variants -s $im_flag -pn $2 -hpc $5 -l $3 -at $att_flag -o greedy -sp S4 -ssp 1
python adv_generator_query.py -m $1 -dj /app/vol/binaries/csv_db/${db_name}/clang_O3.csv -d /app/DB/builds/ -p /app/vol/CFGExtractor/extracted_cfgs_variants -s $im_flag -pn $2 -hpc $5 -l $3 -at $att_flag -o greedy -sp S4 -ssp 2
