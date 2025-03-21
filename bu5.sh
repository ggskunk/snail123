#!/bin/bash

while true; do
    # Eğer output.txt varsa programı sonlandır
    if [ -f "output.txt" ]; then
        echo "✨ Adres bulundu! Program durduruluyor... ✨"
        break
    fi

    # 68-bit aralıkta rastgele bir başlangıç değeri üret
    random_start=$(python3 -c "import random; print(hex(random.randint(0x80000000000000000, 0xFFFFFFFFFFFFFFFFF))[2:].upper())")

    echo "Çalıştırılan komut: ./vanitysearch -gpuId 5 -start $random_start -range 42 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ -o output.txt"

    # VanitySearch çalıştır
    ./vanitysearch -gpuId 5 -o output.txt -start $random_start -range 42 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ

    # Küçük bir bekleme süresi ekleyelim
    sleep 1
done
