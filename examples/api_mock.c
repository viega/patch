/**
 * @file api_mock.c
 * @brief API mocking example for testing.
 *
 * This example demonstrates:
 * - Mocking functions for unit testing
 * - Controlling mock behavior with global state
 * - Verifying function call counts
 * - Simulating errors
 *
 * Build:
 *   cc -std=gnu23 -I../include api_mock.c -L../build -lpatch -o api_mock
 */

#include "patch/patch_hook.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

// ============================================================================
// "Production" code - functions we want to test
// ============================================================================

// Simulated database connection
PATCH_DEFINE_HOOKABLE(bool, db_connect, const char *host, int port)
{
    printf("    [real] Connecting to %s:%d...\n", host, port);
    // In real code, this would actually connect
    return true;
}

PATCH_DEFINE_HOOKABLE(bool, db_query, const char *sql, char *result, size_t result_size)
{
    printf("    [real] Executing: %s\n", sql);
    // In real code, this would execute the query
    snprintf(result, result_size, "Real result");
    return true;
}

PATCH_DEFINE_HOOKABLE(void, db_disconnect, void)
{
    printf("    [real] Disconnecting...\n");
}

// Function under test that uses the database
bool fetch_user_name(int user_id, char *name, size_t name_size)
{
    if (!PATCH_CALL(db_connect, "localhost", 5432)) {
        return false;
    }

    char sql[100];
    snprintf(sql, sizeof(sql), "SELECT name FROM users WHERE id=%d", user_id);

    char result[256];
    bool success = PATCH_CALL(db_query, sql, result, sizeof(result));

    PATCH_CALL(db_disconnect);

    if (success) {
        snprintf(name, name_size, "%s", result);
    }
    return success;
}

// ============================================================================
// Mock infrastructure
// ============================================================================

// Mock state
static struct {
    bool connect_should_succeed;
    bool query_should_succeed;
    const char *query_result;
    int connect_call_count;
    int query_call_count;
    int disconnect_call_count;
    char last_query[256];
} mock_state;

static void reset_mock_state(void)
{
    mock_state.connect_should_succeed = true;
    mock_state.query_should_succeed = true;
    mock_state.query_result = "Mock User";
    mock_state.connect_call_count = 0;
    mock_state.query_call_count = 0;
    mock_state.disconnect_call_count = 0;
    mock_state.last_query[0] = '\0';
}

// Mock implementations
bool mock_db_connect(const char *host, int port)
{
    (void)host;
    (void)port;
    mock_state.connect_call_count++;
    printf("    [mock] db_connect called (will %s)\n",
           mock_state.connect_should_succeed ? "succeed" : "fail");
    return mock_state.connect_should_succeed;
}

bool mock_db_query(const char *sql, char *result, size_t result_size)
{
    mock_state.query_call_count++;
    snprintf(mock_state.last_query, sizeof(mock_state.last_query), "%s", sql);
    printf("    [mock] db_query called with: %s\n", sql);

    if (mock_state.query_should_succeed) {
        snprintf(result, result_size, "%s", mock_state.query_result);
        return true;
    }
    return false;
}

void mock_db_disconnect(void)
{
    mock_state.disconnect_call_count++;
    printf("    [mock] db_disconnect called\n");
}

// ============================================================================
// Test functions
// ============================================================================

static void test_normal_flow(void)
{
    printf("\nTest: Normal flow\n");
    printf("-----------------\n");

    reset_mock_state();
    mock_state.query_result = "John Doe";

    char name[64];
    bool result = fetch_user_name(42, name, sizeof(name));

    printf("  Result: %s\n", result ? "success" : "failure");
    printf("  Name: %s\n", name);
    printf("  Connect calls: %d\n", mock_state.connect_call_count);
    printf("  Query calls: %d\n", mock_state.query_call_count);
    printf("  Disconnect calls: %d\n", mock_state.disconnect_call_count);
    printf("  Query executed: %s\n", mock_state.last_query);

    // Assertions
    if (result && strcmp(name, "John Doe") == 0 &&
        mock_state.connect_call_count == 1 &&
        mock_state.disconnect_call_count == 1) {
        printf("  PASSED\n");
    } else {
        printf("  FAILED\n");
    }
}

static void test_connection_failure(void)
{
    printf("\nTest: Connection failure\n");
    printf("------------------------\n");

    reset_mock_state();
    mock_state.connect_should_succeed = false;

    char name[64] = "unchanged";
    bool result = fetch_user_name(42, name, sizeof(name));

    printf("  Result: %s\n", result ? "success" : "failure");
    printf("  Name: %s\n", name);
    printf("  Query calls: %d (should be 0)\n", mock_state.query_call_count);

    // When connection fails, query should not be called
    if (!result && mock_state.query_call_count == 0) {
        printf("  PASSED\n");
    } else {
        printf("  FAILED\n");
    }
}

static void test_query_failure(void)
{
    printf("\nTest: Query failure\n");
    printf("-------------------\n");

    reset_mock_state();
    mock_state.query_should_succeed = false;

    char name[64] = "unchanged";
    bool result = fetch_user_name(42, name, sizeof(name));

    printf("  Result: %s\n", result ? "success" : "failure");
    printf("  Disconnect calls: %d (should be 1 - cleanup even on failure)\n",
           mock_state.disconnect_call_count);

    // Should still disconnect even when query fails
    if (!result && mock_state.disconnect_call_count == 1) {
        printf("  PASSED\n");
    } else {
        printf("  FAILED\n");
    }
}

int main(void)
{
    printf("=== API Mocking Example ===\n");

    // First, show behavior without mocks
    printf("\nBehavior WITHOUT mocks:\n");
    printf("-----------------------\n");
    char name[64];
    fetch_user_name(1, name, sizeof(name));
    printf("  Got: %s\n", name);

    // Install mocks
    printf("\nInstalling mocks...\n");
    PATCH_HOOK_INSTALL(db_connect, mock_db_connect);
    PATCH_HOOK_INSTALL(db_query, mock_db_query);
    PATCH_HOOK_INSTALL(db_disconnect, mock_db_disconnect);

    // Run tests
    test_normal_flow();
    test_connection_failure();
    test_query_failure();

    // Remove mocks
    printf("\nRemoving mocks...\n");
    PATCH_HOOK_REMOVE(db_connect);
    PATCH_HOOK_REMOVE(db_query);
    PATCH_HOOK_REMOVE(db_disconnect);

    // Verify real functions work again
    printf("\nBehavior AFTER removing mocks:\n");
    printf("------------------------------\n");
    fetch_user_name(1, name, sizeof(name));
    printf("  Got: %s\n", name);

    printf("\n=== Example Complete ===\n");
    return 0;
}
