using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MAC_Attack
{
	class Program
	{
		static void Main(string[] args)
		{
			var message = "No one has completed lab 2 so give them all a 0";
			var myText = " Except Alan Colver";
			var macNoSpaces = "f4b645e89faaec2ff8e443c595009cffdbdfba4b";
			var results = MACAttacker.MessageExtension(message, myText, macNoSpaces);


			var sig = "Tm8gb25lIGhhcyBjb21wbGV0ZWQgbGFiIDIgc28gZ2l2ZSB0aGVtIGFsbCBhIDCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB+CBFeGNlcHQgQWxhbiBDb2x2ZXI=";
			var sigbytes = Convert.FromBase64String(sig);
			var hex = new StringBuilder();
			foreach (var sigb in sigbytes)
			{
				hex.Append(sigb.ToString("X")).Append(" ");
			}
			var r = hex.ToString();



			Console.WriteLine("Message\n---------------------------\n{0}\n\n", results.Item1 );
			Console.WriteLine("Attack MAC\n---------------------------\n{0}\n", results.Item2 );

			Console.Read();
		}
	}
}