SRCS := $(wildcard src/*.c)
HEADERS := $(wildcard src/includes/*.h)

net: $(SRCS) $(HEADERS)
	$(CC) -g -o net $(SRCS)
	
clean:
	@rm net	

.PHONY: clean
