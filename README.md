# DFIR_Toolbar

## menu_config
This is the file that is used to configure the toolbar. The configuration starts out as follows:

```json
{
    "MENU_CONFIG": {
```

The order of the items in the config file will be how they appear in the toolbar.

### Configuring the buttons
The buttons hold the various menus that you can configure. You only need to supply the label of what you want the button to be called.  
The `entries` are what hold the menu items. In this example, there are two buttons; `Websites` and `DFIRRegex`.
```json
{
    "MENU_CONFIG": {
        "Websites": {
            "entries": []
        },
        "DFIRRegex": {
            "entries": []
        }
    }
}
```

### Menu Entries
We'll start off with a simple entry. A menu entry consists of the following elements:  
* label - The name of the entry
* tearoff (true/false) - Optional. Whether it is a tearoff menu. If tearoff is not indicated, it will be false
* command - Optional. The command/plugin associated with the entry. How you want it to act when you click on it.
* image_path - Optional. The path to the image you want to apply to the entry. This is a 16x16 png.  

Lets say we want to add an entry to `Websites` that opens the browser to a website. We want the entry to be named  
`xCyclopedia`. We want the `open_link` plugin to open the site `https://strontic.github.io/xcyclopedia/intro` and  
and we want to display the `strontivy.png` in the entry. We would add the following to the `entries` under `Websites`:

```json
{
    "MENU_CONFIG": {
        "Websites": {
            "entries": [
            {
                    "label": " xCyclopedia",
                    "command": "open_link(https://strontic.github.io/xcyclopedia/intro)",
                    "image_path": "icons/web/stronticy.png"
                }
            ]
        },
        "DFIRRegex": {
            "entries": []
        }
    }
}
```