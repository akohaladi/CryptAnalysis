package cryptanalysis;

import java.util.Arrays;

/**
 * Professor: Dr. Qiao Mengyu
 * CSC 792 : Cyber security project
 * Cryptography Tool
 * @author Akoh Aladiada Rosemary
 */
public class CrpytAnalysisProject {
         
   /* Method to replace all non alphabets with an empty string and convert text
    to upper case */
   public static String replaceText(String text)
   {
      for (int i = 0; i < text.length(); i++ )
            if (!String.valueOf(text.charAt(i)).matches("[a-zA-Z]+"))         
            {
                text = text.replace(String.valueOf(text.charAt(i)), "");
            }
      return text.toUpperCase(); 
   }   
   
// Method to Encrypt the Plaintext using Vegenere Substitution
    public static String VigenereEncrypt(String plainText, String key)
    {    // Initialize cipherText
         String cipherText = ""; 
         // Clean up text
         plainText = replaceText(plainText);
         key = replaceText(key);
         /* Using the key values, loop through each of the characters in the plainText 
         to convert to corresponding character in cipherText */
         for (int i = 0, j = 0; i < plainText.length(); i++)
         {  
             char plainText_char = plainText.charAt(i); 
             cipherText = cipherText + (char) ((plainText_char + key.charAt(j)- 2 * 'A') % 26 + 'A');
             j = j + 1;
             j = j % key.length();
         }
         return cipherText;
    }
    // Method to do the Vigenere Decryption
    public static String VigenereDecrypt(String cipherText, String key)
    {
     
         String plainText = "";
         key = replaceText(key);
         cipherText = replaceText(cipherText);
         /* Using the key values, loop through each of the characters in the cipherText
         to convert to corresponding character in plainText */
         for (int i = 0, j = 0; i < cipherText.length(); i++)
         {  
             char cipherText_char = cipherText.charAt(i); 
             plainText = plainText + (char) (FloorMod(cipherText_char - key.charAt(j), 26) + 'A');
             j = j + 1;
             j = j % key.length();
         }
         return plainText;
    }
    // Method to perform the FloorMod, Returns floormood of the integers passed to it.
    public static int FloorMod(int x, int n)
    {   
        int temp = x % n;
        while (temp < 0 )
            temp = temp + n;
        while (temp >= n)
            temp = temp - n;
        return temp;  
    }
    
    // Method to perform Frequency analysis on each of the 26 letters of the alphabet
    //from user's input cipherText
    public static int [] freqAnalysis(String cipherText) 
    {
        int[] freqArray = new int[26];
        /*Loop through each character(alphabet) in the input cipherText 
        and add it to the frequency array count depending on which character it is*/
        for (int i = 0; i < cipherText.length(); i++ )
            freqArray[(int) cipherText.charAt(i) - (int) 'a'] =
                    freqArray[(int) cipherText.charAt(i) - (int) 'a'] + 1;
            
        return freqArray;
    
    }
    // Method to check if the plainText has alphabets only.
    public static boolean isAlphabet(String check_plainText)
    {
        return check_plainText.matches("[a-zA-Z]+");
    }
    // Method to find Largest number from the Array Input passed
    public static int largestIndex(double arrayInput[])
    {
        double maxNum = arrayInput[1];
        int maxValue = 1;
        int length = arrayInput.length;
        
        // Loop through each number in the input array to find the maximum value
        for ( int i = 1; i < length; i++)
        {
            if (arrayInput[i] > maxNum)
            { 
                maxNum = arrayInput[i];
                maxValue = i;
            }
        }
        return maxValue;
    }
    
    // Method to find the key length(period) depending on the input cipherText 
    public static int keyLength(String cipherText)
    {
        int length = cipherText.length();
        double[] checkArray = new double [length];
        // Loop through potential ksible period (Key Length)
        for (int i = 0; i <= 15; i++)
        {
            checkArray[i] = 0;
            // check to see if the index of checkArray is equal to 0
            if (i == 0)
            {
                continue;
            }
            for (int j = 0; j < length - i; j++)
            {
                if (cipherText.charAt(j) == cipherText.charAt(j + i))
                {
                    checkArray[i] = checkArray[i] + 1;
                }
            }
        }
        /* Call the largestIndex function to find the key length, 
        the largest value in the array is likely the key length*/
        int keyLength = largestIndex(checkArray);
        return keyLength;     
    }
       
    /*Using the Key Length and Input cipherText, a key is found*/
    public static String key(String cipherText, int keyLength)
    {   
        String output = "";
        for ( int i = 0; i < keyLength; i++)
        {
            // Divide cipherText into suubstrings of keylength
            String subCiphertext = "";
            int j = i;
            while (j < cipherText.length())
            {
                subCiphertext = subCiphertext + Character.toString(cipherText.charAt(j));
                j = j + keyLength;
            }
            // Call the freqAnalysis method to perform the frequency analaysis on the subCiphertexts
            int[] freqArray = freqAnalysis(subCiphertext.toLowerCase());
            // Create a 1 D array to store the values
            double[] alphaArray = new double[26];
            for (j = 0; j <= 25; j++)
            {
                alphaArray[j] = (float) freqArray[j] / subCiphertext.length();
            }
            // Create and assign English alphabet frequency values
            double[] letterFreqArray = {0.082, 0.015, 0.028, 0.043, 0.127,
                                        0.022, 0.020, 0.061, 0.070, 0.002, 
                                        0.008, 0.040, 0.024, 0.067, 0.075,
                                        0.019, 0.001, 0.060, 0.063, 0.091, 
                                        0.028, 0.010, 0.023, 0.001, 0.020, 
                                        0.001
                                        };
            double[] newAlphaArray = new double[26];
            Arrays.fill(newAlphaArray, 0);
            // Loop though the array
            for (j = 0; j <= 25; j++)
            {
                for (int k = 0; k<=25; k++)
                {
                    if ((k - j) % 26 >= 0)
                    {
                        newAlphaArray[j] += alphaArray[k] * letterFreqArray[((k -j) % 26)];    
                    }
                    else 
                    {
                        newAlphaArray[j] += alphaArray[k] * letterFreqArray[((k -j) % 26) + 26]; 
                    }
                }
            }
            output+= (char) (((largestIndex(newAlphaArray)) % 26) + 65);
        }
        return output;
    }
     // Method to Encrypt the Plaintext using Columnar Transkition cipher
    public static String columnarEncrypt(String plainText, String key)
    {
          // Initialize cipherText
         String cipherText = "";
         // Call the replaceText method to clean up plainText and key
         plainText = replaceText(plainText);
         key = replaceText(key);
         // Store the user input key into an array
         char [] keyArray = key.toCharArray();
         /*In general, given a simple column transkition with n letters and
         c columns, then there are n / c rows if the remainder is 0, and n /
         c + 1 rows, with r columns have n / c + 1 entries, and c – r columns
         having n / c.*/
         int numLetters = plainText.length();
         // Get number of columns from length of key
         int col = key.length(); 
         int row = numLetters/col;
         if (row != 0)
         {
             row = row + 1; 
         }
         int count = 0;
         // 2D array/matrix to store the rows and columns 
         char [][] matrix = new char [row][col];
         // Fill in the 2D array
         for (int i = 0; i < row; i++)
         {
             for (int j = 0; j < col; j++)
             {
                 if (numLetters == count)
                 {
                     matrix[i][j] = ' ';
                     count --;
                 }
                 else
                 {
                     matrix[i][j] = plainText.charAt(count);
                 }
                 count ++;
                // System.out.println(matrix[i][j]);
             }
             
         }
         int k;
         int keyArrayLen = keyArray.length;
         // sort the keyArray into the sort array
         char [] sortKeyArray = new char [keyArrayLen];
         System.arraycopy(keyArray, 0, sortKeyArray, 0, keyArrayLen);
         Arrays.sort(sortKeyArray);
         for(int i = 0; i < keyArrayLen; i++)
         {
            System.out.println(sortKeyArray[i]);
         }
         
   
         for (int i = 0; i < col; i++)
         {
             // update kition to the index of the sorted array
             k = key.indexOf(sortKeyArray[i]);
             for (int j = 0; j < row; j++)
             {
                 cipherText = cipherText + matrix[j][k];
             }
         }
       
         return cipherText;
    }
   // Method to Decrypt the CipherText using Columnar Transkition cipher
public static String columnarDecrypt(String cipherText, String key)
    {
        // Initialize plainText
        String plainText = "";
         // Call the replaceText method to clean up cipherText and key
        cipherText = replaceText(cipherText);
        key = replaceText(key);
         /*In general, given a simple column transkition with n letters and
         c columns, then there are n / c rows if the remainder is 0, and n /
         c + 1 rows, with r columns have n / c + 1 entries, and c – r columns
         having n / c.*/
         int numLetters = cipherText.length();
         // Get number of columns from length of key
         int col = key.length(); 
         int row = (int)(numLetters/col)+1;
         //int row = numLetters/col;
         int count = 0;
         int k;
         // 2D array/matrix to store the rows and columns 
         char [][] matrix = new char [row][col];
         // A 1D character array to store the cipherText characters
         char [] cipherTextArray = cipherText.toCharArray();
          // A 1D character array to store the key characters
         char [] keyArray = key.toCharArray();
         // Sort the characters/contents of the keyArray
         Arrays.sort(keyArray);
         // Fill in the 2D array
         for (int i = 0; i < col; i++)
         {
             // Update the k to the current element of the array
             k = key.indexOf(keyArray[i]);
             for (int j = 0; j < row; j++)
             {
                 // Fill in the matrix
                 if((j < row-1) || (j == row-1) && (k < col - (col * row - numLetters)))
                 { 
                 matrix[j][k] = cipherTextArray[count];
                 count ++;
                 }
             }
         }
         // Fill in the matrix with the plainText
         for (int i = 0; i < row; i++)
         {
             for(int j = 0; j < col; j++)
                 plainText = plainText + matrix [i][j];
         }
         return plainText;
    }
}

 
        



