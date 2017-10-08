/*
CVE Compare
Version 1.0
Functionality:
Scans software in Windows and compares against the
NIST Vulnerability Database to identify present vulnerabilities.
Includes optional scan for Microsoft hotfixes and patches.
Identifies:
    * Vendor Name
    * Vulnerable Software
    * Software Version
    * CVE Name
    * CVSS V3 Base Severity
    * CVE Description
Hotfix/Patch Scan Identifies:
    * Missing KBs as per identified vulnerabilities
*/
package main

import (
  "bytes"
  "fmt"
  "os"
  "log"
  "os/exec"
  "time"
  "strconv"
  "net/http"
  "io"
  "archive/zip"
  "strings"
  "path/filepath"
  "bufio"
//  "encoding/json"
//  "github.com/jmoiron/jsonq"
)


// Check for errors
func check_error(err error){
  if err != nil {
    panic(err)
  }
}


// Check whether a file already exists.
func check_existence(filename string) bool {
  // If the file exists, return True
  if _, err := os.Stat(filename); !os.IsNotExist(err) {
    return true
  }
  return false
}


// Download a file.
func download(filename string, url string) (err error) {
  // Create the file
  out, err := os.Create(filename)
  check_error(err)
  defer out.Close()

  // Get the data
  resp, err := http.Get(url)
  check_error(err)
  defer resp.Body.Close()

  // Write the body to file
  _, err = io.Copy(out, resp.Body)
  check_error(err)

  return nil
}


// Unzip a file.
func unzip(src, dest string) (err error) {
  reader, err := zip.OpenReader(src)
  check_error(err)
  defer reader.Close()

  for _, f := range reader.File {
    reader_copy, err := f.Open()
    check_error(err)
    defer reader_copy.Close()

    f_path := filepath.Join(dest, f.Name)
    if f.FileInfo().IsDir() {
      os.MkdirAll(f_path, f.Mode())
    } else {
      var f_dir string
      if last_index := strings.LastIndex(f_path,string(os.PathSeparator)); last_index > -1 {
        f_dir = f_path[:last_index]
      }

      err = os.MkdirAll(f_dir, f.Mode())
      if err != nil {
        log.Fatal(err)
        return err
      }

      f, err := os.OpenFile(f_path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
      check_error(err)
      defer f.Close()

      _, err = io.Copy(f, reader_copy)
      check_error(err)
    }
  }
  return nil
}


// Delete a file
func del(filename string) {
  del := os.Remove(filename)
  if del != nil {
    log.Fatal(del)
  }
}


/*
Converts file from XLSX to CSV.
Utilized Python's pandas library to do so.
*/
func xlsx_to_csv() {
  cmd := exec.Command("python.exe", "xlsx_to_csv.py")
  var out bytes.Buffer
  cmd.Stdout = &out
  err := cmd.Run()

  if err != nil {
    log.Fatal(err)
  }
}


// Make a list of unique items from Microsoft Security Bulletin CSV.
func kb_unique_list() {
  cmd := exec.Command("python.exe", "kb_unique_list.py")
  var out bytes.Buffer
  cmd.Stdout = &out
  err := cmd.Run()

  if err != nil {
    log.Fatal(err)
  }
}


// Open and read files line by line.
func open_and_read(fn string) ([]string, error) {

  // Open the file
  file, err := os.Open(fn)
  check_error(err)
  defer file.Close()

  // Read the file.
  var lines []string
  scanner := bufio.NewScanner(file)
  for scanner.Scan() {
    lines = append(lines, scanner.Text())
  }
  return lines, scanner.Err()
}


// Append unique items.
func append_unique(list1 []string, list2 []string) []string {
  for _, item1 := range list1 {
    for _, item2 := range list2 {
      if item1 == item2 {
        return list1
      } else {
        return append(list1, item2)
      }
      }
    }
    return list1
}


// Check for membership; If x in y return true.
func if_in(a string, list []string) bool {
  for _, b := range list {
    if b == a {
      return true
    }
  }
  return false
}


// Run PowerShell command to get a list of all installed hotfixes
func list_hotfixes(kb string) {
  cmd := exec.Command("powershell.exe", "-ep", "Bypass", "Get-HotFix", "-Id", kb)
  var out bytes.Buffer
  cmd.Stdout = &out
  err := cmd.Run()

  if err != nil {
    println(" ")
  }
  // Print the package list
  println(kb)
  //fmt.Printf("%s\n", out.String())
}


/*
Run PowerShell command to get a list of all installed software including:
    * Name
    * Version
    * Vendor
    * Date Installed
*/
func list_packages() {
  cmd := exec.Command("powershell.exe", "-ep", "Bypass", "-File", "scan_installed.ps1")
  var out bytes.Buffer
  cmd.Stdout = &out
  err := cmd.Run()

  if err != nil {
    log.Fatal(err)
  }
  // Print the package list
  fmt.Printf("%s\n", out.String())
}


/*
Download CVE data from NVD for year in (zipped) JSON format
    * URL: https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-<YEAR>.json.zip
    * Unzipped filename: nvdce-1.0-<YEAR>.json
*/
func get_cves() {
  // Oldest available year in JSON format
  year := 2002

  // Current date
  current_year, _, _ := time.Now().Date()

  latest_file := "nvdcve-1.0-" + strconv.Itoa(current_year) + ".json"

  /*
  If latest CVE data has already been downloading, notify user.
  If not, download CVE data up to the latest release.
  */
  if check_existence(latest_file) {
    println("[*] Your CVEs are up to date.\n")
  } else {
    println("[*] Updating CVE data...\n")

    for year <= current_year {
      filename := "nvdcve-1.0-" + strconv.Itoa(year) + ".json.zip"
      url := "https://static.nvd.nist.gov/feeds/json/cve/1.0/" + filename
      unzipped := filename[:len(filename) - 4]

      // Update year to download next file
      year += 1

      // Check if file exists before downloading
      if check_existence(unzipped) {
        continue
      }

      // Download file
      download(filename, url)

      // Extract ZIP contents
      folder := unzipped[:len(unzipped) - 5]
      unzip(filename, folder)

      // Move files to current directory
      original := folder + "/" + unzipped
      new := unzipped
      move := os.Rename(original, new)
      if move != nil {
        println(move)
        return
      }

      // Delete the ZIP files and their respective folders
      del(filename)
      del(folder)

    }
  }
}


/*
Read Microsoft Security Bulletin (MSB); XLSX file.
Compare potential vulnerabilities' CVEs against those in the MSB file.
*/
func compare_bulletin() {
  fn := "BulletinSearch.xlsx"
  url := "http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/" + fn
  csv_file := fn[:len(fn) - 4] + "csv"

  // Check if file exists before downloading
  if check_existence(fn) {
    println("\n[*] You have already downloaded the Security Updates Bulletin.\n")
  } else {
    // Download the bulletin
    download(fn, url)
    }

  if check_existence(csv_file) {
    println("[*] You already have the Security Bulletin CSV file.\n")
  } else {
      // Convert from XLSX to CSV
      xlsx_to_csv()
    }

  // Get a list of missing KBs
  kb_unique_list()

  msb_list := "unique_kb.txt"

  // Unique list of KBs
  unique_list, err := open_and_read(msb_list)
  check_error(err)

  if len(unique_list) == 0 {
    println("[*] No matches found.\n")
  }

  if len(unique_list) > 1 {
    // Compare the KBs against those already installed.
    println("[!] Missing KB:")
    for _, kb := range unique_list {
      // Run PowerShell Get-HotFix to find missing security updates.
      list_hotfixes(kb)
    }
  }

// Delete the temporary KB file
//del(msb_list)

}


/*
Compare CSV file of installed packages against JSON CVE data.
Outputs a file with content that shows:
    * Vendor Name
    * Vulnerable Software
    * Software Version
    * CVE Name
    * CVSS V3 Base Severity
    * CVE Description
*/
func vulnerability_scan() {
  println("[+] Running vulnerability scan...\n\n")
  cmd := exec.Command("python.exe", "vulnerability_scan.py")
  var out bytes.Buffer
  cmd.Stdout = &out
  err := cmd.Run()

  if err != nil {
    log.Fatal(err)
  }

  fmt.Printf("%s", out.String())
}


func main() {
  println("[?] Do you want to run a local scan (L) for installed packages or use an existing file (F)? \n[*] Enter L or F: ")
  var location string
  fmt.Scanln(&location)

  // List installed packages
  if location == "L" {
    list_packages()
  } else if location == "l" {
    list_packages()
  }

  // Get NIST Vulnerability Database CVE data
  get_cves()

  // Run vulnerability scan
  vulnerability_scan()

  // Run scan to see if any hotfixes or patches have been applied
  compare_bulletin()

  println("\n[*] Scan completed. \n")

}
