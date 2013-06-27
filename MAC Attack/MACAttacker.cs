using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Globalization;
using System.Collections;

namespace MAC_Attack
{
	public static class MACAttacker
	{
		/// <summary>
		/// Implements a message extenstion attack
		/// </summary>
		/// <param name="originalMessage">The original message.</param>
		/// <param name="appendedText">The appended text.</param>
		/// <param name="originalHash">The original MAC.</param>
		/// <returns>The new hash/MAC</returns>
		public static Tuple<string,string> MessageExtension(string originalMessage, string appendedText, string originalMAC)
		{
			var sha1 = new SHA1();

			var newText = new byte[64];
			for (int j = 0; j < 64; j++)
				newText[j] = 0x00;

			for (int i = 0; i < appendedText.Length; i++)
				newText[i] = Convert.ToByte(appendedText[i]);

			//AddPadding(ref newText, ((64 + 16 + appendedText.Length) * 8));


			var combinedMessage = ConcatenateByteArrays(FormatToBlock(originalMessage), ConvertStringToBytes(appendedText));
			var attackMAC = sha1.ComputeHash(newText);
			//var attackMAC = sha1.ComputeHash(ConvertStringToBytes(appendedText));

			return new Tuple<string, string>(ByteToHex(combinedMessage), ByteToHex(attackMAC));
		}
		private static void AddPadding(ref byte[] b, int l)
		{
			var k = 83 * 8 + 128;
			// original message + keylength + original padding + new message (792)
			b[62] = 0x03;
			b[63] = 0x18;

			// original message + keylength + new message (656)
			//b[62] = 0x02;
			//b[63] = 0x90;

			// original message + keylength + new message (664)
			//b[62] = 0x02;
			//b[63] = 0x98;

			// 512 + 512 + 128 (1152)
			//b[62] = 0x04;
			//b[63] = 0x80;

			// If the added text is only padded by itself
			//b[63] = 0x98;

			// Added to both regardless
			b[19] = 0x80;

			/*
			for (int i = 1; i <= 8; i++)
			{
				if ((l / 255) > 0)
				{
					b[b.Length - i] = 0xff;
					l -= 256;
				}
				else
				{
					b[b.Length - i] = Convert.ToByte(l);
					b[19] = 0x80;
					return;
				}
			}
			 * */
		}
		// whole message (original (including its padding) + new message (NOT including its padding) + key)
		private static string ByteToHex(byte[] b)
		{
			return String.Join(" ", b.Select(s => s.ToString("X")));
		}
		private static byte[] ConcatenateByteArrays(byte[] block1, byte[] block2)
		{
			var combined = new byte[block1.Length + block2.Length];
			var i = 0;
			for (; i < block1.Length; i++)
			{
				combined[i] = block1[i];
			}

			for (int j = 0; j < block2.Length; j++)
			{
				combined[i] = block2[j];
				i++;
			}

			return combined;
		}
		private static byte[] FormatToBlock(string text)
		{
			var keyLength = 128;
			var paddedText = text.PadRight(512/8, '\0').ToArray();

			var paddedBytes = paddedText.Select(c => Convert.ToByte(c)).ToArray();
			var totalLength = text.Length * 8 + keyLength;
			var secondToLast = totalLength % 255;
			var last = secondToLast == 0 ? totalLength : 255;

			paddedBytes[paddedBytes.Length - 2] = 0x01;
			paddedBytes[paddedBytes.Length - 1] = 0xF8;
			paddedBytes[text.Length] = 0x80;

			return paddedBytes;
		}
		private static byte[] ConvertStringToBytes(string s)
		{
			var values = s.ToCharArray();
			var bytes = new List<byte>();

			foreach (char letter in values)
				bytes.Add(Convert.ToByte(letter));

			return bytes.ToArray();
		}
		private static byte[] StringToByteArray(string hexString)
		{
			if (hexString.Length % 2 != 0)
				throw new ArgumentException(String.Format(CultureInfo.InvariantCulture, "The binary key cannot have an odd number of digits: {0}", hexString));

			var HexAsBytes = new byte[hexString.Length / 2];
			for (int index = 0; index < HexAsBytes.Length; index++)
				HexAsBytes[index] = byte.Parse(hexString.Substring(index * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);

			return HexAsBytes;
		}
	}
}
