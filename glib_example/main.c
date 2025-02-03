/*!
 * \file main.c
 *
 * \brief Example code of using a hash table for key-value pairs.
 */

#include <glib.h>
#include <stdio.h>

/*!
 * \brief Create a hash table from file.
 */
int
create_hash_table_from_file (gchar *filename, GHashTable *table)
{
  FILE *fp;
  char buf[1024];

  /* Just a standard way to open files. */
  fp = fopen (filename, "r");

  /* If file does not exist, exit. */
  if (!fp)
  {
    exit (1);
  }

  /* Read file line by line. */
  while (fgets (buf, sizeof (buf), fp))
  {
    gboolean success = FALSE;
    char *key;
    char *value;

    /* Get the first and the second field. */
    key = strtok (buf, "\t");

    if (!key)
      continue;

    value = strtok (NULL, "\t");

    if (!value)
      continue;

    /* Look up the table for an existing key.
     * If it exists replace it by inserting the new ke-value pair and
     * freeing the old key-value pair */
    char *old_key = NULL;
    char *old_value = NULL;
  
#if 0
    /*Try looking up this key. */
    if (g_hash_table_lookup_extended (table, key, (gpointer *) old_key, (gpointer *) old_value))
    {
      /* Insert the new value */
      printf("insert the new value \n");
      success = g_hash_table_insert (table, g_strdup (key), g_strdup (value));

      /* Just free the key and value */
      g_free (old_key);
      g_free (old_value);
      printf("success : %d \n", success);
    }
    else
    {
      /* Insert into our hash table it is not a duplicate. */
      printf("Insert into our hash table it is not a duplicate.\n");
      g_hash_table_insert (table, g_strdup (key), g_strdup (value));
      printf("success : %d \n", success);

    }
  

#endif
      success = g_hash_table_insert (table, g_strdup (key), g_strdup (value));
      printf("success : %d \n", success);
  }
  /* Close the file when done. */
  fclose (fp);
  return (EXIT_SUCCESS);
}

/*!
 * \brief Dispose of the hash table.
 */
int
destroy_hash_table (GHashTable *table)
{
  g_hash_table_destroy (table);
  return (EXIT_SUCCESS);
}


/*!
 * \brief Remove the entry with the passed key from the hash table.
 */
int
remove_entry (GHashTable *table, char *key)
{
  int result = EXIT_FAILURE;
  char *old_key = NULL;
  char *old_value = NULL;

  /* Try looking up this key */
  if (g_hash_table_lookup_extended (table, key, (gpointer *) old_key, (gpointer *) old_value))
  {
    /* Remove the entry in the hash table. */
    g_hash_table_remove (table, key);

    /* Just free the key and value. */
    g_free( old_key);
    g_free (old_value);
    result = EXIT_SUCCESS;
  }
  else
  {
    fprintf (stderr, "Did not find passed key.");
  }

  return (result);
}


/*!
 * \brief Free a key-value pair inside the hash table.
 */
static void
free_a_hash_table_entry (gpointer key, gpointer value, gpointer user_data)
{
  g_free (key);
  g_free (value);
}


/*!
 * \brief Free all key-value entries in the hash table.
 */
int
free_all_key_value_entries (GHashTable *table)
{
  g_hash_table_foreach (table, free_a_hash_table_entry, NULL);
  return EXIT_SUCCESS;
}


static gboolean
remove_keys_with_A (gpointer key, gpointer value, gpointer user_data)
{
  char *char_value = (char *) value;

  if (char_value[0] == 'A')
  {
    g_free (key);
    g_free (value);
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}


/*!
 * \brief Let's have a main function.
 */
int
main ()
{
  /* Intialise the hash table. */
  GHashTable *table = g_hash_table_new (g_str_hash, g_str_equal);

  int deleted;

  gchar *file_name = strdup ("test.txt");

  create_hash_table_from_file (file_name, table);

  /* Do something with the hash table here. */
  deleted = g_hash_table_foreach_remove (table, remove_keys_with_A, NULL);
  printf ("Deleted %d items!\n", deleted);
  free_all_key_value_entries (table);
  destroy_hash_table (table);
}


/* EOF */
