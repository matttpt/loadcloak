CFLAGS := -Wall -Wextra -Wconversion -Os -std=c99 -D_DEFAULT_SOURCE
LDLIBS := -lm -lrt

loadcloak: loadcloak.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

.PHONY: clean
clean:
	rm -f loadcloak
