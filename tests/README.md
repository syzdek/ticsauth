
TICS Authenticator Tests
========================

Hash and HMAC Tests
-------------------
The HMAC and hash tests are recompiled with differenet data sets and differnt
algorithms so that the following tests are generated:

   * *hash-ALGORITHM-str* generates a hash digest using convenience functions.
   
         tics_hash( algo, data, data_len, md );
         // verify md
   
   * *hash-ALGORITHM-ctx* generates a hash digest using the init, update, and
     result functions.  This also includes test data from the data sets which
     repeat X times.

         tics_hash_init( &ctx, algo );
         tics_hash_update( ctx, data, data_len );
         tics_hash_result( ctx, md );
         // verify md
         tics_hash_free( ctx );
     
   * *hash-ALGORITHM-seg* generates a hash digest multiple times using chunk
     sizes starting at 1 byte with each pass increasing the chunk size by 1
     byte until the chunck size is the same as the length of the input data.
     For input data with a length of 4 bytes, the same hash digest will be
     generated 9 times with different chunck sizes.

         tics_hash_init( &ctx, algo );
         for( chunk = 0; (chunk <= data_len); chunk++)
         {   tics_hash_reset( ctx, algo );
             for(idx = 0; (idx < data_len); idx += chunk)
             {  bytes = (data_len > (idx+chunk))
                      ? chunk
                      : data_len - idx;
                tics_hash_update( ctx, &data[idx], bytes );
             };
             tics_hash_result( ctx, md );
             // verify md
         };
         tics_hash_free( ctx );

   * *hmac-ALGORITHM-str* generates a HMAC hash digest using convenience
     functions.

         tics_hmac( algo, key, key_len, data, data_len, md );
         // verify md

   * *hmac-ALGORITHM-ctx* generates a HMAC hash digest using the init, update,
     and result functions.  This also includes test data from the data sets
     which repeat X times.

         tics_hmac_init( &ctx, algo, key, key_len );
         tics_hmac_update( ctx, data, data_len );
         tics_hmac_result( ctx, md );
         // verify md
         tics_hmac_free( ctx );

   * *hmac-ALGORITHM-seg* generates a HMAC hash digest multiple times by
     entering using chunck sizes starting at 1 byte with each pass increasing
     the chunk size by 1 byte until the chunck size is the same as the length
     of the key.  The data is also entered in chunck sizes.  For input key
     with a length of 4 bytes with input date with a length of 4 bytes, the 
     same digest will be generated 81 times with different chunch sizes.

         tics_hmac_init( &ctx, algo, NULL, 0 );
         for( key_chunk = 0; (key_chunk <= key_len); key_chunk++)
         {  tics_hmac_reset(ctx, algo, 1);
            for( key_idx = 0; (key_idx < key_len); key_idx += key_chunk )
            {  key_bytes = (key_len > (key_idx+key_chunk))
                      ? key_chunk
                      : key_len - key_idx;
               tics_hmac_update_key( ctx, &key[key_idx], key_bytes );
            };
            tics_hmac_update( ctx, NULL, 0 ); // locks key
            
            for( data_chunk = 0; (data_chunk <= data_len); data_chunk++)
            {  tics_hmac_reset(ctx, algo, 0);
               for( data_idx = 0; (data_idx < data_len); data_idx += data_chunk )
               {  data_bytes = (data_len > (data_idx+data_chunk))
                      ? data_chunk
                      : data_len - data_idx;
                  tics_hmac_update( ctx, &data[data_idx], data_bytes );
               };
               tics_hmac_result( ctx, md );
               // verify md
            };
         };
         tics_hmac_free( ctx );
