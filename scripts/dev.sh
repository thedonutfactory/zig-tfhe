#!/bin/bash

# Development script for zig-tfhe

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Zig is installed
check_zig() {
    if ! command -v zig &> /dev/null; then
        print_error "Zig is not installed. Please install Zig 0.12.0 or later."
        print_status "Visit: https://ziglang.org/download/"
        exit 1
    fi
    
    local zig_version=$(zig version)
    print_success "Found Zig: $zig_version"
}

# Build the project
build() {
    print_status "Building zig-tfhe..."
    zig build
    print_success "Build completed successfully!"
}

# Run tests
test() {
    print_status "Running tests..."
    zig build test
    print_success "All tests passed!"
}

# Run examples
run_examples() {
    print_status "Running examples..."
    
    print_status "Running add_two_numbers example..."
    zig build run -- example add_two_numbers
    
    print_status "Running gates_demo example..."
    zig build run -- example gates_demo
    
    print_status "Running security_levels example..."
    zig build run -- example security_levels
    
    print_success "All examples completed!"
}

# Run benchmarks
benchmark() {
    print_status "Running benchmarks..."
    zig build bench
    print_success "Benchmarks completed!"
}

# Clean build artifacts
clean() {
    print_status "Cleaning build artifacts..."
    rm -rf zig-cache zig-out
    print_success "Clean completed!"
}

# Format code
format() {
    print_status "Formatting code..."
    zig fmt src/ examples/ benchmarks/
    print_success "Code formatted!"
}

# Show help
show_help() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build      Build the project"
    echo "  test       Run tests"
    echo "  examples   Run all examples"
    echo "  benchmark  Run benchmarks"
    echo "  clean      Clean build artifacts"
    echo "  format     Format code"
    echo "  all        Run build, test, examples, and benchmark"
    echo "  help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 build"
    echo "  $0 test"
    echo "  $0 all"
}

# Main script logic
main() {
    case "${1:-help}" in
        "build")
            check_zig
            build
            ;;
        "test")
            check_zig
            test
            ;;
        "examples")
            check_zig
            run_examples
            ;;
        "benchmark")
            check_zig
            benchmark
            ;;
        "clean")
            clean
            ;;
        "format")
            check_zig
            format
            ;;
        "all")
            check_zig
            build
            test
            run_examples
            benchmark
            print_success "All tasks completed successfully!"
            ;;
        "help"|*)
            show_help
            ;;
    esac
}

# Run main function with all arguments
main "$@"
