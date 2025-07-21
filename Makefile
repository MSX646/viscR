CC = gcc
CFLAGS = -Wall -Wextra -Werror 
LDFLAGS = -lzstd 
AES_SRC = ./tiny-AES/aes.c
AES_INC = -I./tiny-AES

all: packer stub

#gcc zstd-test.c -o zstd -L../tiny-AES-c/ -laes -I../tiny-AES-c/ -lzstd -lelf -g3
packer: viscR-packer.c 
	$(CC) -o viscR viscR-packer.c $(AES_INC) $(AES_SRC) $(LDFLAGS)

stub: stub.c 
	$(CC) -o stub stub.c $(AES_INC) $(AES_SRC) $(LDFLAGS)
	strip -sxX --remove-section=.bss --remove-section=.comment --remove-section=.eh_frame --remove-section=.eh_frame_hdr --remove-section=.fini --remove-section=.fini_array --remove-section=.gnu.build.attributes --remove-section=.gnu.hash --remove-section=.gnu.version  --remove-section=.got --remove-section=.note.ABI-tag --remove-section=.note.gnu.build-id  --remove-section=.shstrtab --remove-section=.typelink stub

clean:
	rm -f viscR stub *.o

fclean: clean
	rm -f *_protected

re: fclean all

.PHONY: all clean fclean re
