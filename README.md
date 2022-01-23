<div id="top"></div>

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/AR-234/tripwire">
    <h3 align="center">Tripwire</h3>
  </a>

  <p align="center">
    Create a packet monitor on a server in your network that is normally not touched.
    <br />
    Tripwire will inform you if somebody or something does.
    <br />
    <a href="https://github.com/AR-234/tripwire"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/AR-234/tripwire/issues">Report Bug</a>
    ·
    <a href="https://github.com/AR-234/tripwire/issues">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

[![Tripwire Screen Shot][tripwire-screenshot]](https://github.com/AR-234/tripwire)

Tripwire is a packet sniffing tool, which should be installed on a server that 
is untouched in the network. It's job is to provide an early response if somebody 
is scanning the server. 
<br>
Since the server is not in use, any traffic going towards it is suspicious.<br>
And will trigger the tripwire..
<br>
Triggers can be a simple dump or a telegram message.
<br>
If you want any more triggers just create a issue with the idea or send it in yourself.

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple example steps.

### Prerequisites

This is an example of how to list things you need to use the software and how to install them.
* git
* python3

You should also set the SSH Port of the machine to a non standard Port.
Ports can be ignored but you wouldn't see if somebody tries to connect to Port 22.

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/AR-234/tripwire.git
   ```
2. Copy triggers you want from trigger_example to trigger (Some trigger do have configs in the files)

3. Open config.py and change the settings like you need them (more in usage)

4. Run the script with root privileges
```sh
sudo python3 tripwire.py
```
or set a crontab at restart
```sh
sudo crontab -e
```
and add this line
```sh
@restart python3 /home/root/{installation_dir}/tripwire.py
```

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- USAGE EXAMPLES -->
## Usage

Will write a detailed version the next days..

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

Currently nothing is really planed, but you got an idea? Open an "issue" and submit it :)

See the [open issues](https://github.com/AR-234/tripwire/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/AR-234/tripwire.svg?style=flat
[contributors-url]: https://github.com/AR-234/tripwire/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/AR-234/tripwire.svg?style=flat
[forks-url]: https://github.com/AR-234/tripwire/network/members
[stars-shield]: https://img.shields.io/github/stars/AR-234/tripwire.svg?style=flat
[stars-url]: https://github.com/AR-234/tripwire/stargazers
[issues-shield]: https://img.shields.io/github/issues/AR-234/tripwire.svg?style=flat
[issues-url]: https://github.com/AR-234/tripwire/issues
[license-shield]: https://img.shields.io/github/license/AR-234/tripwire.svg?style=flat
[license-url]: https://github.com/AR-234/tripwire/blob/master/LICENSE.txt
[tripwire-screenshot]: https://i.imgur.com/Leun5Cn.png
