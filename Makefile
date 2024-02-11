
makerun:
	@echo "Building the program..."
	rm -f des
	gcc -o des des.c -O3
	@echo "Build complete. Run the program..."
	./des

clean:
	rm -f des
