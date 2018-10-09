function Get-ProcessInfo {
      $array = New-Object System.Collections.ArrayList
      $Script:procInfo = Get-Process | Select Id,Name,Path,Description,VM,WS,CPU,Company | sort -Property Name
      $array.AddRange($procInfo)
      $dataGrid1.DataSource = $array
      $form1.refresh()
}


Add-Type -AssemblyName System.Windows.Forms
$form1 = New-Object system.Windows.Forms.Form
$form1.Size = New-Object System.Drawing.Size(550,500)

$dataGrid1 = New-Object System.Windows.Forms.DataGrid

$dataGrid1.Size = New-Object System.Drawing.Size(492,308)
$dataGrid1.DataBindings.DefaultDataSourceUpdateMode = 0
$dataGrid1.HeaderForeColor = [System.Drawing.Color]::FromArgb(255,0,0,0)
$dataGrid1.Name = "dataGrid1"
$dataGrid1.DataMember = ""
$dataGrid1.TabIndex = 0
$dataGrid1.Location = New-Object System.Drawing.Point(13,48)
$form1.Controls.Add($dataGrid1)


$OnLoadForm_UpdateGrid=
{
    Get-ProcessInfo
}

$form1.add_Load($OnLoadForm_UpdateGrid)

# Add Button
$button1 = New-Object System.Windows.Forms.Button
$button1.Location = New-Object System.Drawing.Size(35,400)
$button1.Size = New-Object System.Drawing.Size(120,23)
$button1.Text = "RELOAD"

$form1.Controls.Add($button1)


$button1_OnClick=
{
      Get-ProcessInfo
}

$button1.add_Click($button1_OnClick)


$form1.ShowDialog()
