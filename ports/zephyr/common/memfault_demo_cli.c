//! @file
//!
//! Copyright (c) Memfault, Inc.
//! See License.txt for details
//!
//! @brief
//! Adds a basic set of commands for interacting with Memfault SDK

#include "memfault/demo/cli.h"

#include <shell/shell.h>

#include "memfault_zephyr_http.h"

static int prv_clear_core_cmd(const struct shell *shell, size_t argc, char **argv) {
  return memfault_demo_cli_cmd_clear_core(argc, argv);
}

static int prv_get_core_cmd(const struct shell *shell, size_t argc, char **argv) {
  return memfault_demo_cli_cmd_get_core(argc, argv);
}

static int prv_crash_example(const struct shell *shell, size_t argc, char **argv) {
  return memfault_demo_cli_cmd_crash(argc, argv);
}

static int prv_get_device_info(const struct shell *shell, size_t argc, char **argv) {
  return memfault_demo_cli_cmd_get_device_info(argc, argv);
}

static int prv_print_chunk_cmd(const struct shell *shell, size_t argc, char **argv) {
  return memfault_demo_cli_cmd_print_chunk(argc, argv);
}

static int prv_post_chunk_cmd(const struct shell *shell, size_t argc, char **argv) {
#if defined(CONFIG_MEMFAULT_HTTP_SUPPORT)
  return memfault_zephyr_port_post_data();
#else
  shell_print(shell, "CONFIG_MEMFAULT_HTTP_SUPPORT not enabled");
  return 0;
#endif
}

#if defined(CONFIG_MEMFAULT_HTTP_SUPPORT)
typedef struct {
  const struct shell *shell;
  size_t total_size;
} sMemfaultShellOtaDownloadCtx;

static bool prv_handle_update_available(const sMemfaultOtaInfo *info, void *user_ctx) {
  sMemfaultShellOtaDownloadCtx *ctx = (sMemfaultShellOtaDownloadCtx *)user_ctx;
  shell_print(ctx->shell, "Downloading OTA payload, size=%d bytes", (int)info->size);
  return true;
}

static bool prv_handle_data(void *buf, size_t buf_len, void *user_ctx) {
  // this is an example cli command so we just drop the data on the floor
  // a real implementation could save the data in this callback!
  return true;
}

static bool prv_handle_download_complete(void *user_ctx) {
  sMemfaultShellOtaDownloadCtx *ctx = (sMemfaultShellOtaDownloadCtx *)user_ctx;
  shell_print(ctx->shell, "OTA download complete!");
  return true;
}
#endif /* CONFIG_MEMFAULT_HTTP_SUPPORT */

static int prv_check_and_fetch_ota_payload_cmd(const struct shell *shell, size_t argc, char **argv) {
#if defined(CONFIG_MEMFAULT_HTTP_SUPPORT)
  uint8_t working_buf[256];

  sMemfaultShellOtaDownloadCtx user_ctx = {
    .shell = shell,
  };

  sMemfaultOtaUpdateHandler handler = {
    .buf = working_buf,
    .buf_len = sizeof(working_buf),
    .user_ctx = &user_ctx,
    .handle_update_available = prv_handle_update_available,
    .handle_data = prv_handle_data,
    .handle_download_complete = prv_handle_download_complete,
  };

  shell_print(shell, "Checking for OTA update");
  int rv = memfault_zephyr_port_ota_update(&handler);
  if (rv == 0) {
    shell_print(shell, "Up to date!");
  } else if (rv < 0) {
    shell_print(shell, "OTA update failed, rv=%d, errno=%d", rv, errno);
  }
  return rv;
#else
  shell_print(shell, "CONFIG_MEMFAULT_HTTP_SUPPORT not enabled");
  return 0;
#endif
}

SHELL_STATIC_SUBCMD_SET_CREATE(
    sub_memfault_cmds,
    SHELL_CMD(crash, NULL, "trigger a crash", prv_crash_example),
    SHELL_CMD(clear_core, NULL, "clear the core", prv_clear_core_cmd),
    SHELL_CMD(get_core, NULL, "gets the core", prv_get_core_cmd),
    SHELL_CMD(get_device_info, NULL, "display device information", prv_get_device_info),
    SHELL_CMD(print_chunk, NULL, "get next Memfault data chunk to send and print as a curl command",
              prv_print_chunk_cmd),
    SHELL_CMD(post_chunk, NULL, "get next Memfault data chunk to send and POST it to the Memfault cloud",
              prv_post_chunk_cmd),
    SHELL_CMD(get_latest_release, NULL, "checks to see if new ota payload is available", prv_check_and_fetch_ota_payload_cmd),
    SHELL_SUBCMD_SET_END /* Array terminated. */
);

SHELL_CMD_REGISTER(mflt, &sub_memfault_cmds, "Memfault Test Commands", NULL);
