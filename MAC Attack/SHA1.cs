﻿using System;

namespace MAC_Attack
{
	/// <summary>Computes the SHA1 hash for the input data using the managed library.</summary>
	public class SHA1 : BlockHashAlgorithm
	{
		private uint[] accumulator;


		/// <summary>Initializes a new instance of the SHA1 class.</summary>
		public SHA1()
			: base(64)
		{
			lock (this)
			{
				HashSizeValue = 160;
				accumulator = new uint[5];
				Initialize();
			}
		}


		/// <summary>Initializes the algorithm.</summary>
		override public void Initialize()
		{
			lock (this)
			{
				
				accumulator[0] = 0xf4b645e8;
				accumulator[1] = 0x9faaec2f;
				accumulator[2] = 0xf8e443c5;
				accumulator[3] = 0x95009c16;
				accumulator[4] = 0xdbdfba4b;
				
				/*
				accumulator[0] = 0x67452301;
				accumulator[1] = 0xEFCDAB89;
				accumulator[2] = 0x98BADCFE;
				accumulator[3] = 0x10325476;
				accumulator[4] = 0xC3D2E1F0;
				*/
				base.Initialize();
			}
		}


		/// <summary>Process a block of data.</summary>
		/// <param name="inputBuffer">The block of data to process.</param>
		/// <param name="inputOffset">Where to start in the block.</param>
		override protected void ProcessBlock(byte[] inputBuffer, int inputOffset)
		{
			lock (this)
			{
				uint[] workBuffer = new uint[80];
				uint A = accumulator[0];
				uint B = accumulator[1];
				uint C = accumulator[2];
				uint D = accumulator[3];
				uint E = accumulator[4];
				uint j;

				uint[] temp = Utilities.ByteToUInt(inputBuffer, inputOffset, BlockSize, EndianType.BigEndian);
				Array.Copy(temp, 0, workBuffer, 0, temp.Length);
				for (int i = 16; i < 80; i++)
				{
					j = workBuffer[i - 16] ^ workBuffer[i - 14] ^ workBuffer[i - 8] ^ workBuffer[i - 3];
					workBuffer[i] = (j << 1) | (j >> -1);
				}

				#region Round 1
				E += Utilities.RotateLeft(A, 5) + F1(B, C, D) + workBuffer[0]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F1(A, B, C) + workBuffer[1]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F1(E, A, B) + workBuffer[2]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F1(D, E, A) + workBuffer[3]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F1(C, D, E) + workBuffer[4]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F1(B, C, D) + workBuffer[5]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F1(A, B, C) + workBuffer[6]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F1(E, A, B) + workBuffer[7]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F1(D, E, A) + workBuffer[8]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F1(C, D, E) + workBuffer[9]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F1(B, C, D) + workBuffer[10]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F1(A, B, C) + workBuffer[11]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F1(E, A, B) + workBuffer[12]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F1(D, E, A) + workBuffer[13]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F1(C, D, E) + workBuffer[14]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F1(B, C, D) + workBuffer[15]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F1(A, B, C) + workBuffer[16]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F1(E, A, B) + workBuffer[17]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F1(D, E, A) + workBuffer[18]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F1(C, D, E) + workBuffer[19]; C = Utilities.RotateLeft(C, 30);
				#endregion

				#region Round 2
				E += Utilities.RotateLeft(A, 5) + F2(B, C, D) + workBuffer[20]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F2(A, B, C) + workBuffer[21]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F2(E, A, B) + workBuffer[22]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F2(D, E, A) + workBuffer[23]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F2(C, D, E) + workBuffer[24]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F2(B, C, D) + workBuffer[25]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F2(A, B, C) + workBuffer[26]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F2(E, A, B) + workBuffer[27]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F2(D, E, A) + workBuffer[28]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F2(C, D, E) + workBuffer[29]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F2(B, C, D) + workBuffer[30]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F2(A, B, C) + workBuffer[31]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F2(E, A, B) + workBuffer[32]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F2(D, E, A) + workBuffer[33]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F2(C, D, E) + workBuffer[34]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F2(B, C, D) + workBuffer[35]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F2(A, B, C) + workBuffer[36]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F2(E, A, B) + workBuffer[37]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F2(D, E, A) + workBuffer[38]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F2(C, D, E) + workBuffer[39]; C = Utilities.RotateLeft(C, 30);
				#endregion

				#region Round 3
				E += Utilities.RotateLeft(A, 5) + F3(B, C, D) + workBuffer[40]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F3(A, B, C) + workBuffer[41]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F3(E, A, B) + workBuffer[42]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F3(D, E, A) + workBuffer[43]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F3(C, D, E) + workBuffer[44]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F3(B, C, D) + workBuffer[45]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F3(A, B, C) + workBuffer[46]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F3(E, A, B) + workBuffer[47]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F3(D, E, A) + workBuffer[48]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F3(C, D, E) + workBuffer[49]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F3(B, C, D) + workBuffer[50]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F3(A, B, C) + workBuffer[51]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F3(E, A, B) + workBuffer[52]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F3(D, E, A) + workBuffer[53]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F3(C, D, E) + workBuffer[54]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F3(B, C, D) + workBuffer[55]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F3(A, B, C) + workBuffer[56]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F3(E, A, B) + workBuffer[57]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F3(D, E, A) + workBuffer[58]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F3(C, D, E) + workBuffer[59]; C = Utilities.RotateLeft(C, 30);
				#endregion

				#region Round 4
				E += Utilities.RotateLeft(A, 5) + F4(B, C, D) + workBuffer[60]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F4(A, B, C) + workBuffer[61]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F4(E, A, B) + workBuffer[62]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F4(D, E, A) + workBuffer[63]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F4(C, D, E) + workBuffer[64]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F4(B, C, D) + workBuffer[65]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F4(A, B, C) + workBuffer[66]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F4(E, A, B) + workBuffer[67]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F4(D, E, A) + workBuffer[68]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F4(C, D, E) + workBuffer[69]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F4(B, C, D) + workBuffer[70]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F4(A, B, C) + workBuffer[71]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F4(E, A, B) + workBuffer[72]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F4(D, E, A) + workBuffer[73]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F4(C, D, E) + workBuffer[74]; C = Utilities.RotateLeft(C, 30);
				E += Utilities.RotateLeft(A, 5) + F4(B, C, D) + workBuffer[75]; B = Utilities.RotateLeft(B, 30);
				D += Utilities.RotateLeft(E, 5) + F4(A, B, C) + workBuffer[76]; A = Utilities.RotateLeft(A, 30);
				C += Utilities.RotateLeft(D, 5) + F4(E, A, B) + workBuffer[77]; E = Utilities.RotateLeft(E, 30);
				B += Utilities.RotateLeft(C, 5) + F4(D, E, A) + workBuffer[78]; D = Utilities.RotateLeft(D, 30);
				A += Utilities.RotateLeft(B, 5) + F4(C, D, E) + workBuffer[79]; C = Utilities.RotateLeft(C, 30);
				#endregion

				accumulator[0] += A;
				accumulator[1] += B;
				accumulator[2] += C;
				accumulator[3] += D;
				accumulator[4] += E;
			}
		}


		/// <summary>Process the last block of data.</summary>
		/// <param name="inputBuffer">The block of data to process.</param>
		/// <param name="inputOffset">Where to start in the block.</param>
		/// <param name="inputCount">How many bytes need to be processed.</param>
		override protected byte[] ProcessFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
		{
			lock (this)
			{
				byte[] temp;
				int paddingSize;
				ulong size;

				// Figure out how much padding is needed between the last byte and the size.
				paddingSize = (int)(((ulong)inputCount + (ulong)Count) % (ulong)BlockSize);
				paddingSize = (BlockSize - 8) - paddingSize;
				if (paddingSize < 1) { paddingSize += BlockSize; }

				// Create the final, padded block(s).
				temp = new byte[inputCount + paddingSize + 8];
				Array.Copy(inputBuffer, inputOffset, temp, 0, inputCount);
				temp[inputCount] = 0x80;
				size = ((ulong)Count + (ulong)inputCount) * 8;
				Array.Copy(Utilities.ULongToByte(size, EndianType.BigEndian), 0, temp, (inputCount + paddingSize), 8);

				// Push the final block(s) into the calculation.
				ProcessBlock(temp, 0);
				if (temp.Length == (BlockSize * 2))
				{
					ProcessBlock(temp, BlockSize);
				}

				return Utilities.UIntToByte(accumulator, EndianType.BigEndian);
			}
		}


		private uint F1(uint a, uint b, uint c)
		{
			return (c ^ (a & (b ^ c))) + 0x5A827999;
		}

		private uint F2(uint a, uint b, uint c)
		{
			return (a ^ b ^ c) + 0x6ED9EBA1;
		}

		private uint F3(uint a, uint b, uint c)
		{
			return ((a & b) | (c & (a | b))) + 0x8F1BBCDC;
		}

		private uint F4(uint a, uint b, uint c)
		{
			return (a ^ b ^ c) + 0xCA62C1D6;
		}
	}
}