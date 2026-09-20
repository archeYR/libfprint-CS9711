/*
 * Copyright (C) 2026 AkosCz
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <glib.h>

#include "drivers/cs9711/cs9711.h"

static void
test_scan_error_action (void)
{
  g_autoptr(GError) cancelled = NULL;
  g_autoptr(GError) disconnected = NULL;

  cancelled = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                   "cancelled");
  disconnected = g_error_new_literal (G_USB_DEVICE_ERROR,
                                      G_USB_DEVICE_ERROR_NO_DEVICE,
                                      "disconnected");

  g_assert_cmpint (cs9711_scan_error_action (cancelled, TRUE), ==,
                   CS9711_SCAN_ERROR_COMPLETE);
  g_assert_cmpint (cs9711_scan_error_action (cancelled, FALSE), ==,
                   CS9711_SCAN_ERROR_FAIL);
  g_assert_cmpint (cs9711_scan_error_action (disconnected, TRUE), ==,
                   CS9711_SCAN_ERROR_FAIL);
}

static void
test_deactivate_action (void)
{
  g_assert_cmpint (cs9711_deactivate_action (TRUE), ==,
                   CS9711_DEACTIVATE_WAIT_FOR_SCAN);
  g_assert_cmpint (cs9711_deactivate_action (FALSE), ==,
                   CS9711_DEACTIVATE_COMPLETE);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/cs9711/scan-error-action", test_scan_error_action);
  g_test_add_func ("/cs9711/deactivate-action", test_deactivate_action);

  return g_test_run ();
}
