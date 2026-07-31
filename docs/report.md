
<div style="text-align:justify">

# 1. Tujuan
Laporan ini merinci analisis kriptografi dan eksploitasi terhadap _stream cipher_ yang saat ini masih aktif digunakan di dalam sistem internal perusahaan. Tujuan utama dari laporan ini adalah untuk mengevaluasi ketahanan dari sistem enkripsi _Linear Feedback Shift Register (LSFR) 128-bit_.

Meskipun sistem ini menggunakan ukuran _state_ internal 128-bit yang sepintas terlihat memadai, analisis saya menemukan bahwa adanya kelemahan fundamental pada desain linear cipher tersebut. Dengan menggunakan metode _known-plaintext attack_, saya berhasil mengeksploitasi hubungan linear ini untuk memetakan _state_ cipher ke dalam sistem persamaan yang dapat diselesaikan. Hal ini memungkinan pemulihan penuh dari initial _state_ (seed) rahasia serta _decryption_ menyeluruh dari _payload_ target, yang membuktikan bahwa sistem tersebut sudah tidak layak lagi untuk digunakan untuk mengamankan data sensitif.

# 2. Analisis Keamanan Cipher LSFR Legacy (Task A.1)
Evaluasi terhadap implementasi _Linear Feedback Shift Register (LSFR)_ menunjukkan bahwa sistem ini memiliki kelemahan yang membuatnya sangat rentan dan tidak layak digunakan sebagai pengaman data modern. Analisis ini mencakup beberapa point utama :
- **LSFR beroperasi menggunakan operasi linear** : Karena tidak ada bagian non-linear yang dilibatkan (seperti misalnya S-boxes pada cipher modern), seluruh _keystream_ dapat dimodelkan secara persis sebagai kombinasi linear.

- **State recovery** : Oleh karena linearitas ini, penyerang mampu melakukan rekonstruksi ulang seluruh status internal cipher. Dengan menggunakan _known-plaintext attack_, bit keystream yang terekspos dapat dipetakan ke dalam sistem persamaan linear. Hal ini memungkinan penyerang untuk menyelesaikan persamaan tersebut dan mendapatkan kembali _seed_ rahasia.

-  **Ukuran state 128-bit tidak menjamin keamanan** : Pertahanan berbasis _security-through-obscurity_ dengan ukuran state yang besar menjadi tidak efektif ketika struktur matematika yang digunakan dapat direduksi menjadi sistem persamaan matrix.

- **Impact dari Constant ^ 1** : _Feedback_ pada sistem ini menyertakan sebuah _constant_ ^ 1 ($x^{128} + x^{31} + x^{13} + x^3 + 1$). Meskipun penambahan _constant_ ini mengubah sistem menjadi _affine function_, hal ini dapat diatasi dengan mudah di dalam matriks melalui penyesuaian vector _constant_, sehingga tidak memberikan tambahan perlindungan yang berarti. 


# 3. Sistem Linear GF(2) (Task A.2)
Untuk melakukan konstruksi ulang _seed_ rahasia sepanjang 128-bit, kita harus memetakan hubungan antara 128-bit state awal dengan bit-bit keystream yang dihasilkan ke dalam sistem persamaan linear dalam _Galois Field 2_ (GF(2)).

### A. Ekstraksi Keystream melalui Known-Plaintext
Berdasarkan spesifikasi, enkripsi dilakukan dengan operasi XOR antara _plaintext_ dan _keystream_ ($C = P \oplus K$). Karena pada _challenge hint_ ditulis bahwa 16 byte pertama dari _plaintext_ tersebut adalah `SYSTEM_OVERFLOW!`, kita dapat mengekstrak 128 bit keystream pertama (K) dengan melakukan XOR pada 16 byte pertama _ciphertext_ (C) dengan header yang diketahui :

$$K_i = C_i \oplus P_i \quad \text{untuk } i = 0, 1, \dots, 127$$
### B. Pemodelan Matrix 128 x 129
Setiap bit _keystream_ yang dihasilkan merupakan kombinasi linear dari _state_ register awal akibat _shift_ berulang dan _feedback function_ (feedback polynomial : $x^{128} + x^{31} + x^{13} + x^3 + 1$).
1. **Symbolic Tracking** : Algoritma melacak bagaimana 128 bit _seed_ awal ($s_0, s_1, \dots, s_{127}$) melakukan _shift_ dan bercampur melalui operasi XOR pada posisi tap (127, 30, 12, 2)
2. **Constant $\oplus 1$** : _Feedback_ pada sistem ini menyertakan _constant_ $\oplus 1$. _Constant_ ini diperhitungkan di dalam matrix dengan menyesuaikan kolom constant (b) agar sesuai dengan _shift_ dari _constant_ tersebut.
3. **Bentuk matrix** : Hasil akhirnya adalah sistem persamaan linear yang dipresentasikan dalam bentuk matrix [A | b] berukuran 128 x 129, dimana matrix A berisi koefisien relasi bit _seed_ dan kolom terakhir (b) berisi bit _keystream_ hasil ekstrasi

# 4. Eksekusi Serangan dan Pemulihan State (Task A.3 & Task A.4)
Bagian ini merincikan langkah-langkah teknis dan alur eksekusi yang dilakukan program `cryptanalysis_tool.py`.

### A. Ekstraksi Keystream
Fase pertama berfokus pada isolasi variabel yang diketahui. Sistem membaca `ciphertext.hex` dan melakukan _decode_ ke dalam bentuk _raw bytes_. 16 _byte_ pertama dari _ciphertext_ tersebut kemudian dikenakan operasi XOR terhadap header _plaintext_ yang telah diketahui (`SYSTEM_OVERFLOW!`). Hal ini mengekspos 128 bit pertama dari keystream yang dihasilkan oleh LSFR.

### B. Penyelesaian Sistem dengan Gauss Elimination dalam GF(2)
Sebanyak 128 bit _keystream_ yang terekstrak diproses melalui algoritma _Symbolic Tracking_ untuk mengonstruksi matrix 128 x 129. Matrix ini selanjutnya diproses menggunakan algoritma _Gauss Elimination_ yang diimplementasikan menggunakan Python tanpa _library_ external.

Fungsi _solver_ melakukan _Pivot Search_, _Swapping_, dan _Forward Eliminatiion_ menggunakan operasi XOR, lalu dilanjutkan dengan _Back-Substitution_. Proses ini mereduksi sistem linear dan mengisolasi nilai dari ke-128 variable _state_ awal.

### C. Hasil Pemulihan Seed
Penyelesaian matrix ini menghasilkan vector solusi yang mewakili 128 bit _state_ awal. Semua bit ini dikonversi kembali menjadi _hexadecimal_ standar. 
- Seed yang dipulihkan : `948264be3ca698cdbca996b49d79406e`

### D. Payload dan FLAG
Dengan seed awal yang valid, LSFR dapat disimulasikan ulang untuk memproduksi sisa _keystream_ buatan yang panjangnya sama dengan total ukuran _ciphertext_. _Keystream_ buatan ini kemudian dikenakan XOR dengan seluruh _byte_ _ciphertext_ untuk membalikkan proses enkripsi. 

Proses dekripsi ini mengekspos secara keseluruhan teks rahasia secara utuh. FLAG berhasil ditemukan setelah 16 _byte_ _header_ awal :
- FLAG : `FLAG{28C6BBACF707DA2A}`

# 5. Analisis Kompleksitas Algoritma (Task A.5)
Dalam konteks ini, N merepresentasikan ukuran _state_ internal, yaitu N = 128.

### A. Time Complexity : $O(N^3)$
- **Pivot Search** : Untuk setiap kolom, algoritma mencari baris ke bawah untuk menemukan nilai 1. Proses ini memakan waktu $O(N)$ pada setiap kolom.
- **Forward Elimination** : Untuk setiap kolom pivot (terdapat N kolom), algoritma mengiterasi baris-baris di bawahnya (maksimal N baris), dan pada setiap baris melakukan operasi XOR pada setiap elemen (sepanjang N elemen). _Triple Nested Loop_ ini menghasilkan kompleksitas $O(N^3)$. 
- **Back-Substitution** : Algoritma ini berjalan mundur dari baris paling bawah ke atas, melakukan substitusi nilai ke variabel di atasnya. Karena menggunakan _Double nested loop_ ini memiliki kompleksitas $O(N^2)$
- **Kesimpulan** : Karena tahap _forward elimination_ mendominasi kalkulasi, maka kompleksitas waktu yang diambil adalah $O(N^3)$. Untuk ukuran N = 128, maka total operasi berada di kisaran $128^3$, yaitu sekitar 2.097.152 operasi.

### B. Space Complexity : $O(N^2)$ 
- **Penyimpanan Matrix** : Algoritma yang dipakai harus memuat seluruh relasi linear ke dalam memori. Sistem ini menggunakan matrix dua dimensi berupa _list_ di dalam _list_ dengan ukuran N x (N + 1). Sehingga _Space Complexity_ nya adalah $O(N^2)$ 
- **Vector Hasil** : Struktur data vector yang digunakan hanyalah sebuah _array_ berukuran N untuk menyimpan hasil solusi. _Space complexity_ nya adalah $O(N)$.
- **Kesimpulan** : Karena penyimpanan matrix mendominasi memori, _Space Complexity_ nya adalah $O(N^2)$.


# 6. Kesimpulan
### A. Kesimpulan Analisis
Berdasarkan hasil pengujian yang telah dilakukan, dapat disimpulkan bahwa penggunaan LSFR ini secara fundamental tidak aman. Penggunaan operasi linear murni tanpa adanya komponen non-linear mengakibatkan keselurahan sistem dapat direduksi menjadi persamaan linear dengan _Galois Field 2_ (GF(2)).

Meskipun memiliki _keyspace_ sebesar 128-bit yang dimana secara teori cukup untuk menahan _brute-force attack_, kelemahan matematisnya memungkinan penyerang dengan akses ke sebagain _plaintext_ untuk mengekstrak _state_ awal hanya dalam hitungan detik. Sistem ini sudah tidak lagi relevan dan sangat berbahaya bila digunakan untuk melindungi data penting.

### B. Rekomendasi
Untuk memitigasi kelemahan ini, sistem ini harus segera dihapus dan diganti dengan standar kriptografi modern, seperti misalnya _AES-256-GCM_. 

Keunggulan dari _AES-256-GCM_ ini adalah :
- **Non-linear** : Berbeda dengan _LSFR_, _AES_ menggunakan komponen non-linear yang disebut _S-Boxes_. Hal ini mencegah segala serangan berbasis persamaan linear seperti _Gauss Elimination_.
- **Authenticated Encryption with Associated Data** : _GCM_ menghasilkan _Authentication Tag_ yang memastikan bahwa _ciphertext_ tidak dimanipulasi atau diubah oleh pihak ketiga selama pengiriman dan penyimpanan.
- **Standar Industri** : _AES-256-GCM_ merupakan standar enkripsi yang direkomendasikan oleh lembaga seperti NIST dan memenuhi persyaratan keamanan data modern.
</div>
