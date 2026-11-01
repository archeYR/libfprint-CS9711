#include "fpi-context.h"
#include "fpi-device.h"

static void
test_variants (void)
{
  g_autoptr(GArray) types = fpi_get_driver_types ();
  guint legacy = 0;
  guint acl16 = 0;

  for (guint i = 0; i < types->len; i++)
    {
      GType type = g_array_index (types, GType, i);
      g_autoptr(FpDeviceClass) klass = g_type_class_ref (type);

      if (g_strcmp0 (klass->id, "cs9711") != 0)
        continue;

      g_autoptr(FpDevice) device = g_object_new (type, NULL);

      g_assert_cmpint (fp_device_get_nr_enroll_stages (device), ==, 15);
      for (const FpIdEntry *entry = klass->id_table; entry->vid; entry++)
        {
          g_assert_cmpuint (entry->vid, ==, 0x2541);
          if (entry->pid == 0x2549)
            {
              acl16++;
              g_assert_cmpint (klass->temp_hot_seconds, ==, -1);
              g_assert_true (fp_device_has_feature (device, FP_DEVICE_FEATURE_ALWAYS_ON));
              g_assert_cmpuint (entry->driver_data, !=, 0);
            }
          else
            {
              legacy++;
              g_assert_true (entry->pid == 0x0236 || entry->pid == 0x9711);
              g_assert_cmpint (klass->temp_hot_seconds, ==, 0);
              g_assert_false (fp_device_has_feature (device, FP_DEVICE_FEATURE_ALWAYS_ON));
              g_assert_cmpuint (entry->driver_data, ==, 0);
            }
        }
    }

  g_assert_cmpuint (legacy, ==, 2);
  g_assert_cmpuint (acl16, ==, 1);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/cs9711/variants", test_variants);
  return g_test_run ();
}
