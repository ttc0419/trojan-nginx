CC = /usr/bin/gcc
CFLAGS = -std=c17 -Wall -pipe -march=native
LDFLAGS = -Wl,--build-id=none -lcrypto -lanl

all: trojan echo-server echo-client socks5-client stage

config-build-type:
ifeq ($(build_type), release)
	@echo "Builing release version..."
	$(eval CFLAGS += -O3 -flto -s)
else
	@echo "Building debug version..."
	$(eval CFLAGS += -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -O0 -g -fsanitize=address -fsanitize=undefined)
endif

trojan: config-build-type src/server.c
	$(CC) $(CFLAGS) $(filter-out $<,$^) $(LDFLAGS) -o $@

echo-server: config-build-type src/test/echo-server.c
	$(CC) $(CFLAGS) $(filter-out $<,$^) $(LDFLAGS) -o $@

echo-client: config-build-type src/test/echo-client.c
	$(CC) $(CFLAGS) $(filter-out $<,$^) $(LDFLAGS) -o $@

socks5-client: config-build-type src/test/socks5-client.c
	$(CC) $(CFLAGS) $(filter-out $<,$^) $(LDFLAGS) -o $@

stage: config-build-type src/test/stage.c
	$(CC) $(CFLAGS) $(filter-out $<,$^) $(LDFLAGS) -o $@

clean:
	rm -rf trojan echo-server echo-client socks5-client stage *.dSYM/ src/test/a.out
