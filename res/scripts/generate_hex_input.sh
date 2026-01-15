hexdump -vn1024 -e'4/4 "%08X" 1 "\n"' /dev/urandom >| input_hex.txt
