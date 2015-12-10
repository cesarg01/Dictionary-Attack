import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Scanner;
import javax.swing.JFrame;

public class PasswordCracker {

	private final HashSet<String> hashes;
	private final ArrayList<String> passwords;
	public String type;

	PasswordCracker() {
		hashes = new HashSet<String>();
		passwords = new ArrayList<String>();
	}

	public void readHashFile(String file) {
		try (BufferedReader reader = Files.newBufferedReader(Paths.get(file),
				Charset.forName("UTF-8"))) {
			String line = null;

			while ((line = reader.readLine()) != null) {
				if (line != null) {
					String[] words = line.split("\\s");

					for (String w : words) {
						if (!w.equals(null)
								&& (!w.equals("") && !w.equals(" "))) {
							this.hashes.add(w);
						}
					}
				}
			}
		} catch (IOException e) {
			System.out.println("Invalid path for file " + file);
		}
	}

	public void readPassFile(String file) {
		try (BufferedReader reader = Files.newBufferedReader(Paths.get(file),
				Charset.forName("UTF-8"))) {
			String line = null;

			while ((line = reader.readLine()) != null) {
				if (line != null) {
					String[] words = line.split("\\s");

					for (String w : words) {
						if (!w.equals(null)
								&& (!w.equals("") && !w.equals(" "))) {
							this.passwords.add(w);
						}
					}
				}
			}
		} catch (IOException e) {
			System.out.println("Invalid path for file " + file);
		}
	}

	private static String convertToHex(byte[] data) {
		StringBuffer buffer = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			if (((i % 4) == 0) && (i != 0))
				buffer.append("");
			int x = (int) data[i];
			if (x < 0)
				x += 256;
			if (x < 16)
				buffer.append("0");
			buffer.append(Integer.toString(x, 16));
		}
		return buffer.toString();
	}

	public static String sha1(String text) {

		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-1");

			byte[] sha1hash = new byte[40];

			md.update(text.getBytes("iso-8859-1"), 0, text.length());
			sha1hash = md.digest();

			return convertToHex(sha1hash);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "Sha1 Failed";

	}

	public static String sha256(String base) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(base.getBytes("UTF-8"));
			StringBuffer hexString = new StringBuffer();

			for (int i = 0; i < hash.length; i++) {
				String hex = Integer.toHexString(0xff & hash[i]);
				if (hex.length() == 1)
					hexString.append('0');
				hexString.append(hex);
			}

			return hexString.toString();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	public static String md5Java(String password) {
		String digest = null;
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] hash = md.digest(password.getBytes("UTF-8"));

			// converting byte array to Hexadecimal String
			StringBuilder sb = new StringBuilder(2 * hash.length);
			for (byte b : hash) {
				sb.append(String.format("%02x", b & 0xff));
			}

			digest = sb.toString();

		} catch (UnsupportedEncodingException ex) {
			System.out.println("oops I messed up encoding " + password);
		} catch (NoSuchAlgorithmException ex) {
			System.out.println("No Algorithm " + password);
		}
		return digest;
	}

	public int regularWords(BufferedWriter writer) {
		int count = 0;
		for (String s : this.passwords) {
			if (checkHash(s, writer)) {
				count++;
			}
		}
		return count;
	}

	public int trailNum(BufferedWriter writer) {
		int count = 0;
		for (String s : this.passwords) {

			for (int i = 0; i < 10; i++) {
				String newString = s + i;
				if (checkHash(newString, writer)) {
					count++;
				}
			}

		}
		return count;
	}

	public int numReplace(BufferedWriter writer) {
		int count = 0;
		for (String s : this.passwords) {
			String newString = null;
			for (int i = 0; i < s.length(); i++) {
				if (s.charAt(i) == 'i') {
					newString = s.substring(0, i) + "1" + s.substring(i + 1);
				} else if (s.charAt(i) == 'a') {
					newString = s.substring(0, i) + "4" + s.substring(i + 1);
				} else if (s.charAt(i) == 'e') {
					newString = s.substring(0, i) + "3" + s.substring(i + 1);
					// System.out.println(newString);
				} else if (s.charAt(i) == 'o') {
					newString = s.substring(0, i) + "0" + s.substring(i + 1);
					// System.out.println(newString);
				} else if (s.charAt(i) == 'g') {
					newString = s.substring(0, i) + "6" + s.substring(i + 1);
					// System.out.println(newString);
				} else if (s.charAt(i) == 's') {
					newString = s.substring(0, i) + "5" + s.substring(i + 1);
				}
				if (newString != null) {
					if (checkHash(newString, writer)) {
						count++;
					}
				}
			}
		}
		return count;
	}

	public int oneCap(BufferedWriter writer) {
		int count = 0;
		for (String s : this.passwords) {

			for (int i = 0; i < s.length(); i++) {

				String newString = s.substring(0, i)
						+ s.substring(i, i + 1).toUpperCase()
						+ s.substring(i + 1);
				// System.out.println(up);
				if (checkHash(newString, writer)) {
					count++;
				}
			}
		}
		return count;
	}

	public int trailingExclam(BufferedWriter writer) {
		int count = 0;
		for (String s : this.passwords) {
			String newString = s + "!";
			if (checkHash(newString, writer)) {
				count++;
			}
		}
		return count;
	}

	public int twoCap(BufferedWriter writer) {
		int count = 0;
		for (String s : this.passwords) {

			for (int i = 0; i < s.length(); i++) {
				for (int j = 0; j < s.length(); j++) {
					if ((s.charAt(i) >= 97) && (s.charAt(i) <= 122)
							&& (s.charAt(j) >= 97) && (s.charAt(j) <= 122)
							&& (j > i)) {
						String newString = s.substring(0, i)
								+ s.substring(i, i + 1).toUpperCase()
								+ s.substring(i + 1, j)
								+ s.substring(j, j + 1).toUpperCase()
								+ s.substring(j + 1);
						if (checkHash(newString, writer)) {
							count++;
						}
					}
				}
			}
		}
		return count;
	}

	public int oneCapOneNum(BufferedWriter writer) {
		int count = 0;
		for (String s : this.passwords) {
			for (int i = 0; i < s.length(); i++) {
				for (int j = 0; j < s.length(); j++) {
					if ((s.charAt(i) >= 97) && (s.charAt(i) <= 122)) {
						String newString = "";
						if (s.charAt(i) == 'i') {
							newString = s.substring(0, i) + "1"
									+ s.substring(i + 1);
							newString = newString.substring(0, j)
									+ newString.substring(j, j + 1)
											.toUpperCase()
									+ newString.substring(j + 1);
							// System.out.println(newString);
						} else if (s.charAt(i) == 'a') {
							newString = s.substring(0, i) + "4"
									+ s.substring(i + 1);
							newString = newString.substring(0, j)
									+ newString.substring(j, j + 1)
											.toUpperCase()
									+ newString.substring(j + 1);
							// System.out.println(newString);
						} else if (s.charAt(i) == 'e') {
							newString = s.substring(0, i) + "3"
									+ s.substring(i + 1);
							newString = newString.substring(0, j)
									+ newString.substring(j, j + 1)
											.toUpperCase()
									+ newString.substring(j + 1);
							// System.out.println(newString);
						} else if (s.charAt(i) == 'o') {
							newString = s.substring(0, i) + "0"
									+ s.substring(i + 1);
							newString = newString.substring(0, j)
									+ newString.substring(j, j + 1)
											.toUpperCase()
									+ newString.substring(j + 1);
							// System.out.println(newString);
						} else if (s.charAt(i) == 'g') {
							newString = s.substring(0, i) + "6"
									+ s.substring(i + 1);
							newString = newString.substring(0, j)
									+ newString.substring(j, j + 1)
											.toUpperCase()
									+ newString.substring(j + 1);
							// System.out.println(newString);
						} else if (s.charAt(i) == 's') {
							newString = s.substring(0, i) + "5"
									+ s.substring(i + 1);
							newString = newString.substring(0, j)
									+ newString.substring(j, j + 1)
											.toUpperCase()
									+ newString.substring(j + 1);
							// System.out.println(newString);
						} else {

						}
						if (checkHash(newString, writer)) {
							count++;
						}
					}
				}
			}
		}
		return count;
	}

	public int combineWords(BufferedWriter writer) {
		int count = 0;
		for (String s : this.passwords) {
			for (String st : this.passwords) {
				if (!s.equals(st)) {
					String newString = s + st;
					if (checkHash(newString, writer)) {
						count++;
					}
				}
			}
		}
		return count;
	}

	public static double getTime() {
		return System.currentTimeMillis() + 0.0;
	}

	public boolean checkHash(String word, BufferedWriter writer) {
		try {
			String hash;
			if (this.type.equalsIgnoreCase("md5")) {
				hash = md5Java(word);
			} else if (this.type.equalsIgnoreCase("sha1")) {
				hash = sha1(word);
			} else {
				hash = sha256(word);
			}
			if (this.hashes.contains(hash)) {
				writer.write("Found " + hash + " = " + word);
				writer.newLine();
				this.hashes.remove(hash);
				return true;
			} else {
				return false;
			}
		} catch (IOException e) {
			System.out.println("Could not write to file");
		}
		return false;
	}

	public static void printTime(double start, double current) {
		double time = ((current + 0.0) - (start + 0.0)) / 1000;
		System.out.println("Time since last call: " + (time) + " seconds");
	}

	public static void main(String[] args) {

		try (BufferedWriter writer = Files.newBufferedWriter(
				Paths.get("PasswordCrackReport.txt"), Charset.forName("UTF-8"))) {
			PasswordCracker pC = new PasswordCracker();
			Scanner scan = new Scanner(System.in);

			boolean extra = false;

			System.out.println("Would you like to do the very intensive check? Can take up to 20 minutes (y/n)");
			String response = scan.nextLine();
			if (response.equalsIgnoreCase("y")) {
				extra = true;
			}

			if (args.length < 1) {
				System.out.println("Please provide file of password hashes.");
				System.out.println("Usage:");
				System.out.println("java PasswordCracker <File of hashes>");
				System.out.println(" -or-");
				System.out
						.println("PasswordCracker <File of hashes> <Dictionary File>");
				System.exit(0);
			}
			System.out
					.println("What type of hashing would you like to use? (md5, sha1, sha256)");
			Scanner sc = new Scanner(System.in);
			String type = sc.nextLine();
			if (type.equalsIgnoreCase("md5") || type.equalsIgnoreCase("sha1")
					|| type.equalsIgnoreCase("sha256"))
				pC.type = type;
			else {
				System.out.println("Please enter a valid hashing name");
				System.exit(0);
			}
			System.out
					.println("Do you want to test the adding two words together? (y/n) (Takes approx. 20 minutes)");
			if (sc.nextLine().equals("y"))
				extra = true;
			sc.close();

			String hashFile = args[0];
			String passFile;

			if (args.length > 1) {
				passFile = args[1];
			} else {
				// passFile = "10k most common.txt";
				passFile = "passwords.txt";
				System.out.println("Using default file of common passwords: "
						+ passFile);
			}

			pC.readHashFile(hashFile);
			pC.readPassFile(passFile);
			int passCount = pC.hashes.size();

			int globalCount = 0;
			double oldCurr = 0.0;
			double elapsedTime = 0.0;
			double[] data = new double[8];

			final double startTime = System.currentTimeMillis();

			// Case one - Will sysout word + hash
			System.err.println("Default list...");
			globalCount += pC.regularWords(writer);
			double currTime = getTime();
			System.err.println("Finished");
			double time = ((currTime + 0.0) - (startTime + 0.0)) / 1000;
			writer.write("Cracked lowercase passwords in: " + time + " seconds");
			writer.newLine();
			writer.newLine();
			data[0] = time;

			// Case two - pass plus number at end
			System.err.println("Trailing number...");
			globalCount += pC.trailNum(writer);
			oldCurr = currTime;
			currTime = getTime();
			System.err.println("Finished");
			time = ((currTime + 0.0) - (oldCurr + 0.0)) / 1000;
			writer.write("Cracked lowercase with trailing number passwords in: "
					+ time + " seconds");
			writer.newLine();
			writer.newLine();
			data[1] = time;

			// Case three - replacing letters
			System.err.println("Number replace...");
			globalCount += pC.numReplace(writer);
			oldCurr = currTime;
			currTime = getTime();
			System.err.println("Finished");
			time = ((currTime + 0.0) - (oldCurr + 0.0)) / 1000;
			writer.write("Cracked lowercase with number replacement in: "
					+ time + " seconds");
			writer.newLine();
			writer.newLine();
			data[2] = time;

			// Case four - One uppercase Letter
			System.err.println("One uppercase...");
			globalCount += pC.oneCap(writer);
			oldCurr = currTime;
			currTime = getTime();
			System.err.println("Finished");
			time = ((currTime + 0.0) - (oldCurr + 0.0)) / 1000;
			writer.write("Cracked lowercase with 1 capital replacement in: "
					+ time + " seconds");
			writer.newLine();
			writer.newLine();
			data[3] = time;

			// Two uppercase letters
			System.err.println("Two uppercase...");
			globalCount += pC.twoCap(writer);
			oldCurr = currTime;
			currTime = getTime();
			System.err.println("Finished");
			time = ((currTime + 0.0) - (oldCurr + 0.0)) / 1000;
			writer.write("Cracked lowercase with 2 capital replacement in: "
					+ time + " seconds");
			writer.newLine();
			writer.newLine();
			data[4] = time;

			// One uppercase one number
			System.err.println("One uppercase one number...");
			globalCount += pC.oneCapOneNum(writer);
			oldCurr = currTime;
			currTime = getTime();
			System.err.println("Finished");
			time = ((currTime + 0.0) - (oldCurr + 0.0)) / 1000;
			writer.write("Cracked lowercase with 1 capital and 1 lowercase replacement in: "
					+ time + " seconds");
			writer.newLine();
			writer.newLine();
			data[5] = time;

			// Trailing exclamation point
			System.err.println("Trailing exclamation...");
			globalCount += pC.trailingExclam(writer);
			oldCurr = currTime;
			currTime = getTime();
			System.err.println("Finished");
			time = ((currTime + 0.0) - (oldCurr + 0.0)) / 1000;
			elapsedTime = ((currTime + 0.0) - (startTime + 0.0));
			writer.write("Cracked lowercase with trailing exclamation point in: "
					+ time + " seconds");
			writer.newLine();
			writer.newLine();
			data[6] = time;
			writer.write("Total time for \"quick\" modifications: "
					+ (elapsedTime / 1000) + " seconds");
			writer.newLine();

			// All combinations of 2 words
			if (extra) {
				System.err.println("Combining words...");
				System.err.println("NOTE: This takes approx. 20 minutes");
				globalCount += pC.combineWords(writer);
				oldCurr = currTime;
				currTime = getTime();
				System.err.println("Finished");
				time = ((currTime + 0.0) - (oldCurr + 0.0)) / 1000;
				writer.write("Cracked combined words in: " + time + " seconds");
				writer.newLine();
				data[7] = time;
				writer.write("That is "
						+ (((time - (elapsedTime/1000)) / (elapsedTime/1000)) * 100)
						+ "% longer than the \"quick\" solutions");
				writer.newLine();
				writer.newLine();
				double rate = (840332549999999.0 / (49995000/time));
				writer.write("Since the strongest passwords are just 3 words put together, at this rate all 8.4e+14 "
						+ "combinations of that would take " + rate + " seconds");
				writer.newLine();
				writer.write("Which is equivalent to " + (rate/60/60/24/30/12) + " years");
				writer.newLine();
			}

			

			writer.newLine();
			writer.write("Found " + globalCount + " of " + passCount
					+ " passwords");
			writer.newLine();

			writer.write("Total execution time: "
					+ ((currTime - startTime) / 1000) + " seconds");

			

		} catch (IOException e) {
			System.out.println("Could not find file!");
		}

	}

}