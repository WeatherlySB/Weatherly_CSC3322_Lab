#include <unistd.h>
 #include <stdio.h>      // for printf, fprintf
#include <stdlib.h>     // for EXIT_SUCCESS, EXIT_FAILURE, calloc
#include <string.h>     // for strcmp, strlen, strlcpy
#include <errno.h>      // for errno
#include <stdint.h>     // for uintptr_t
#include <signal.h>
#include <ctype.h>      // for isprint, isspace



    int validate_request(const char *request, size_t length);
    int scan_for_shellcode(const char *input);
    void sanitized_process_request(const char *sanitized_input);
 
 // Shellcode that would spawn a shell when executed
 // (Simplified representation of actual attack code)
 char shellcode[] = 
	 "\x90\x90\x90\x90\x90\x90\x90\x90"  // NOP sled to increase chances of successful exploit
	 "\x31\xc0\x50\x68\x2f\x2f\x73\x68"  // Assembly instructions that when executed
	 "\x68\x2f\x62\x69\x6e\x89\xe3\x50"  // would call execve("/bin/sh", NULL, NULL)
	 "\x53\x89\xe1\xb0\x0b\xcd\x80";     // This is actual x86 shellcode
 
 void process_finger_request(char *input) {
	 char buffer[256];  // Fixed-size buffer (vulnerable to overflow)
	 int (*return_function)() = NULL;    // Function pointer to demonstrate return address overwrite
	 
	 printf("[Server] Received request: %s\n", input);
	 printf("[Server] Buffer at memory address: %p\n", buffer);
	 printf("[Server] Return function pointer at: %p\n", &return_function);
	 
	 // Log the memory layout for educational purposes
	 printf("[Server] Memory layout (low to high):\n");
	 printf("         [buffer (256 bytes)][return_function][saved frame pointer][return address]\n\n");
	 
	 // THE VULNERABLE FUNCTION:
	 // This is the exact vulnerability the Morris Worm exploited
	 strcpy(buffer, input);  // Unsafe copy without bounds checking
	 
	 printf("[Server] After copy - buffer now contains: %.50s%s\n", 
			buffer, strlen(buffer) > 50 ? "..." : "");
	 
	 // If the return function pointer was overwritten, it will no longer be NULL
	 if (return_function != NULL) {
		 printf("[Server] SECURITY BREACH DETECTED! return_function was overwritten to %p\n", return_function);
		 // In a real exploit, the worm would jump to the malicious code at this point
	 }
	 
	 printf("[Server] Processing finger request...\n");
 }
 
 /*
  * Generate an attack string that would:
  * 1. Fill the buffer with the NOP sled and shellcode
  * 2. Overwrite the return address to point back into our buffer
  */
 void generate_morris_attack(char *attack_string, size_t attack_size, void *target_buffer) {
	 size_t i;
	 unsigned long target_addr;
	 
	 // In a real attack, the Morris Worm would guess or calculate this address
	 // We're simplifying by using the actual buffer address + offset to aim at our NOP sled
	 target_addr = (unsigned long)target_buffer + 64; // Aim somewhere in the NOP sled
	 
	 // Clear the buffer
	 memset(attack_string, 0, attack_size);
	 
	 // Build the attack string:
	 // 1. Fill the start with NOP sled (0x90)
	 for (i = 0; i < 128; i++) {
		 attack_string[i] = 0x90;  // NOP instruction
	 }
	 
	 // 2. Place the shellcode after the NOP sled
	 memcpy(attack_string + 128, shellcode, strlen(shellcode));
	 
	 // 3. Fill the rest until return address with dummy data
	 for (i = 128 + strlen(shellcode); i < 272; i++) {
		 attack_string[i] = 'A';
	 }
	 
	 // 4. Overwrite return function pointer with address pointing back to our shellcode
	 *((unsigned long *)(attack_string + 272)) = target_addr;
	 
	 // Display for educational purposes
	 printf("[Attack] Generated Morris-style attack payload:\n");
	 printf("         - NOP sled (128 bytes)\n");
	 printf("         - Shellcode (%lu bytes)\n", strlen(shellcode));
	 printf("         - Padding to reach return address\n");
	 printf("         - Overwritten return address: %p\n", (void *)target_addr);
 }



/**
 * Securely processes a finger request with proper bounds checking
 * and security measures to prevent buffer overflow attacks
 * 
 * @param input The input string to process
 * @param input_size The maximum size of the input buffer
 * @return 0 on success, non-zero on error
 */
 int secure_process_finger_request(const char *input, size_t input_size) {
    // Verify input parameters
    if (input == NULL) {
        fprintf(stderr, "[Error] NULL input provided to secure_process_finger_request\n");
        return -1;
    }
    
    // Define a properly sized buffer with room for null terminator
    char buffer[256];
    memset(buffer, 0, sizeof(buffer)); // Initialize to prevent information leakage
    
    // Demonstration variable (not used in secure implementation)
    volatile int security_check = 0xCAFEBABE; // Canary value for demonstration
    
    printf("[Server] Received request of length %zu\n", strlen(input));
    
    // Print basic info for educational purposes
    printf("[Server] Buffer at memory address: %p\n", buffer);
    printf("[Server] Security check value at: %p\n", &security_check);
    
    // Log the memory layout for educational purposes
    printf("[Server] Memory layout with protections (low to high):\n");
    printf("         [stack canary][buffer (256 bytes)][security_check][saved frame pointer][return address]\n\n");
    
    // Check input length before copying - KEY SECURITY CHECK
    if (strlen(input) >= sizeof(buffer)) {
        fprintf(stderr, "[Security] ATTACK PREVENTED: Input length (%zu) exceeds buffer size (%zu)\n", 
                strlen(input), sizeof(buffer) - 1);
        // Log potential attack details
        printf("[Security] First 50 bytes of suspicious input: %.50s%s\n", 
               input, strlen(input) > 50 ? "..." : "");
        return -2; // Indicate potential attack
    }
    
    // SECURE VERSION:
    // Use safer string functions with bounds checking
    #ifdef HAVE_STRLCPY
        // Using strlcpy if available (BSD systems, security-focused libraries)
        strlcpy(buffer, input, sizeof(buffer));
    #else
        // Fallback to strncpy + explicit null termination on other systems
        strncpy(buffer, input, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0'; // Ensure null termination
    #endif
    
    // Verify our security check value hasn't been tampered with
    if (security_check != 0xCAFEBABE) {
        fprintf(stderr, "[Security] BREACH ATTEMPT DETECTED: Memory corruption identified\n");
        return -3; // Security breach detected
    }
    
    printf("[Server] After secure copy - buffer contains: %.50s%s\n", 
           buffer, strlen(buffer) > 50 ? "..." : "");
    
    // Security scanning of input (simplified example)
    if (scan_for_shellcode(buffer)) {
        fprintf(stderr, "[Security] ATTACK PREVENTED: Potential shellcode detected in input\n");
        return -4;
    }
    
    // Process the request with proper input sanitization
    printf("[Server] Securely processing finger request...\n");
    
    // Actually process the finger request (simplified for demo)
    sanitized_process_request(buffer);
    
    return 0; // Success
}

/**
 * Helper function to scan for potential shellcode patterns
 * In a real implementation, this would use more sophisticated detection
 */
int scan_for_shellcode(const char *input) {
    // Simple heuristic checks for demonstration purposes
    // Real implementations would use more sophisticated pattern matching
    
    // Check for NOP sleds (consecutive 0x90 bytes)
    int consecutive_nops = 0;
    for (size_t i = 0; i < strlen(input); i++) {
        if ((unsigned char)input[i] == 0x90) {
            consecutive_nops++;
            if (consecutive_nops > 5) {
                fprintf(stderr, "[Security] Detected potential NOP sled at position %zu\n", i - consecutive_nops + 1);
                return 1; // Potential shellcode detected
            }
        } else {
            consecutive_nops = 0;
        }
    }
    
    // Check for common shellcode patterns (simplified)
    // In reality, pattern matching would be more comprehensive
    const char *shellcode_patterns[] = {
        "/bin/sh",
        "/bin/bash",
        "execve",
        "\x31\xc0\x50\x68", // Common x86 shellcode start sequence
        NULL
    };
    
    for (int i = 0; shellcode_patterns[i] != NULL; i++) {
        if (strstr(input, shellcode_patterns[i])) {
            fprintf(stderr, "[Security] Detected suspicious pattern: %s\n", shellcode_patterns[i]);
            return 1; // Potential shellcode detected
        }
    }
    
    // Check for high concentration of non-printable characters
    int non_printable_count = 0;
    for (size_t i = 0; i < strlen(input); i++) {
        if (!isprint(input[i]) && !isspace(input[i])) {
            non_printable_count++;
        }
    }
    
    if ((float)non_printable_count / strlen(input) > 0.3) {
        fprintf(stderr, "[Security] Suspicious number of non-printable characters: %d out of %zu\n", 
                non_printable_count, strlen(input));
        return 1; // Potential binary content in what should be text
    }
    
    return 0; // No obvious shellcode detected
}

/**
 * Actually process the finger request after sanitization
 * This is a placeholder for whatever the finger service would actually do
 */
void sanitized_process_request(const char *sanitized_input) {
    // In a real finger daemon, this would look up user information
    // and return it to the client
    printf("[Server] Looking up user: %s\n", sanitized_input);
    
    // Implement actual finger lookup logic here
    // ...
    
    printf("[Server] Finger request completed successfully\n");
}

void signal_handler(int signal_num) {
    fprintf(stderr, "[Signal Handler] Caught signal: %d\n", signal_num);
    exit(EXIT_FAILURE);
}

 
int validate_request(const char *request, size_t length) {
    // Example simple validation: reject if "attack" is found
    if (strstr(request, "attack") != NULL) {
        return -1;  // Detected malicious input
    }
    return 0;  // Safe input
}

 

 int main(int argc, char *argv[]) {
    char request[1024] = {0};  // Initialize to zero for safety
    char *manual_payload = NULL;
    void *buffer_addr = NULL;
    
    // Set up signal handlers for unexpected errors
    if (signal(SIGSEGV, signal_handler) == SIG_ERR) {
        fprintf(stderr, "[Error] Failed to set up signal handler for SIGSEGV\n");
        return EXIT_FAILURE;
    }
    // Validate command-line arguments
    if (argc > 1) {
        if (argc < 3 && strcmp(argv[1], "--simulate-attack") == 0) {
            fprintf(stderr, "[Error] Insufficient arguments for simulation mode\n");
            fprintf(stderr, "Usage: %s --simulate-attack 0xADDRESS\n", argv[0]);
            return EXIT_FAILURE;
        }
        
        if (strcmp(argv[1], "--simulate-attack") == 0) {
            // Simulation mode with proper error checking
            
            // First call with safe input to get buffer address
            printf("[Info] Probing for buffer address...\n");
            if (strlcpy(request, "probe", sizeof(request)) >= sizeof(request)) {
                fprintf(stderr, "[Error] Probe string truncated\n");
                return EXIT_FAILURE;
            }
            
            process_finger_request(request);
            
            // Parse the address with error checking
            char *endptr;
            errno = 0;  // Reset errno to detect conversion errors
            buffer_addr = (void *)strtoul(argv[2], &endptr, 0);
            
            // Check for conversion errors
            if (errno != 0 || *endptr != '\0' || endptr == argv[2]) {
                fprintf(stderr, "[Error] Invalid buffer address: %s\n", argv[2]);
                fprintf(stderr, "Address must be a valid hexadecimal value (e.g., 0xbfff1234)\n");
                return EXIT_FAILURE;
            }
            
            if (buffer_addr == NULL) {
                fprintf(stderr, "[Error] Buffer address cannot be NULL\n");
                return EXIT_FAILURE;
            }
            
            // Validate address range (basic sanity check)
            if ((uintptr_t)buffer_addr < 0x10000 || (uintptr_t)buffer_addr > 0xFFFFFFFF) {
                fprintf(stderr, "[Warning] Buffer address 0x%lx seems unusual. Proceed with caution.\n", 
                        (unsigned long)buffer_addr);
            }
            
            // Allocate with error checking and secure initialization
            manual_payload = (char *)calloc(1024, 1);  // Use calloc to zero-initialize memory
            if (!manual_payload) {
                perror("[Error] Memory allocation failed");
                return EXIT_FAILURE;
            }
            
            printf("\n[Demo] Simulating attack payload generation...\n");
            generate_morris_attack(manual_payload, 1024, buffer_addr);       // Generate the Morris Worm attack
            
            // Execute with safety checks
            printf("\n[Demo] Demonstrating attack prevention mechanisms...\n");
            
            // In a real secure system, we'd validate the input before processing
            if (validate_request(manual_payload, 1024) != 0) {
                printf("[Security] Attack payload detected and blocked!\n");
                free(manual_payload);
                return EXIT_SUCCESS;
            }
            
            // Otherwise, process normally (with secure handling)
            secure_process_finger_request(manual_payload, 1024);
            
            printf("\n[Demo] In a secure system, the buffer overflow would be prevented\n");
            printf("[Info] Security measures demonstrated:\n");
            printf("       - Input validation and bounds checking\n");
            printf("       - Use of safe string functions (strlcpy instead of strcpy)\n");
            printf("       - Stack protection mechanisms\n");
            printf("       - Proper error handling\n");
            
            free(manual_payload);
            manual_payload = NULL;  // Prevent use-after-free
        } else {
            // Unknown command line option
            fprintf(stderr, "[Error] Unknown option: %s\n", argv[1]);
            fprintf(stderr, "Usage: %s [--simulate-attack 0xADDRESS]\n", argv[0]);
            return EXIT_FAILURE;
        }
    } else {
        // Interactive mode with proper security
        printf("This program demonstrates how to safely handle user input\n");
        printf("Enter a finger request: ");
        
        // Securely read input with size limit
        if (fgets(request, sizeof(request), stdin) == NULL) {
            fprintf(stderr, "[Error] Failed to read input\n");
            return EXIT_FAILURE;
        }
        
        // Check for input too long (line didn't end)
        size_t input_len = strlen(request);
        if (input_len > 0 && request[input_len - 1] != '\n') {
            fprintf(stderr, "[Error] Input too long, potential buffer overflow attack\n");
            
            // Flush the remainder of the line
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            
            return EXIT_FAILURE;
        }
        
        // Remove trailing newline safely
        if (input_len > 0 && request[input_len - 1] == '\n') {
            request[input_len - 1] = '\0';
        }
        
        // Validate input before processing
        if (validate_request(request, sizeof(request)) != 0) {
            printf("[Security] Potentially malicious input detected and blocked!\n");
            return EXIT_SUCCESS;
        }
        
        // Process the request with secure function
        secure_process_finger_request(request, sizeof(request));
        
    }
    
    return EXIT_SUCCESS;
}