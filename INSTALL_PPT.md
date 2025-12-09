# How to Create PowerPoint Presentation

## Quick Start

### Option 1: Automated Generation (Recommended)

1. **Install python-pptx:**
```bash
pip install python-pptx
```

2. **Run the script:**
```bash
python create_presentation.py
```

3. **Open the generated file:**
- File will be saved as `SplitSmart_Presentation.pptx`
- Open with Microsoft PowerPoint or Google Slides

### Option 2: Manual Creation

1. **Open Microsoft PowerPoint** (or Google Slides)

2. **Use PRESENTATION.md as content guide:**
   - Each "# Slide X" section represents one slide
   - Copy content from PRESENTATION.md
   - Format as needed

3. **Add visual elements:**
   - Architecture diagrams
   - Attack flow diagrams
   - Code snippets (use code formatting)
   - Screenshots from demos

### Option 3: Markdown to PPT Converters

**Online Tools:**
- [Marp](https://marp.app/) - Markdown presentation ecosystem
- [Slideas](https://www.slideas.app/) - Markdown to PowerPoint
- [Deckset](https://www.deckset.com/) - Mac only

**Steps:**
1. Upload `PRESENTATION.md`
2. Configure styling
3. Export as PowerPoint

## Presentation Structure

The presentation includes **22 slides** covering:

1. Title Slide
2. Project Overview
3. Application Architecture
4. Threat Model (4 Attacks)
5. Cryptographic Architecture
6-9. Defense Against Each Attack
10. Blockchain Ledger
11. Cryptographic Algorithms
12. Implementation Details
13-14. Demonstrations
15. Security Properties
16. Performance & Scalability
17. Comparison
18. Real-World Applications
19. Best Practices
20. Future Enhancements
21. Conclusion
22. Q&A

## Visual Elements to Add

### Diagrams Needed:
1. **System Architecture Diagram**
   - Client, Server, Database components
   - Data flow between components

2. **Three-Layer Security Architecture**
   - Layer 1: Key Exchange
   - Layer 2: Signatures
   - Layer 3: Encryption

3. **Attack Flow Diagrams** (for each attack)
   - Normal flow
   - Attack attempt
   - Defense mechanism

4. **Blockchain Structure Diagram**
   - Genesis block
   - Block chain
   - Hash links

### Screenshots to Include:
- Demo outputs showing attacks being prevented
- Web UI showing blockchain ledger
- Code snippets from key implementations

## Tips for Presentation

### Design:
- Use consistent color scheme (blue/green for security)
- Keep slides uncluttered
- Use bullet points effectively
- Include code snippets in monospace font

### Content:
- Explain each attack clearly
- Show how defense works
- Demonstrate with actual demos if possible
- Highlight security properties achieved

### Delivery:
- Practice running the demos live
- Be ready to explain cryptographic concepts
- Prepare for questions about implementation
- Have backup slides for detailed technical questions

## Running Demos During Presentation

### Quick Demo Commands:
```bash
# Basic functionality
python main.py demo

# Individual attacks
python demos/demo_eavesdropping.py
python demos/demo_modification.py
python demos/demo_spoofing.py
python demos/demo_replay.py
python demos/demo_tampering.py

# Web UI
python web_app.py
```

### Demo Tips:
- Run demos in advance to ensure they work
- Have screenshots ready as backup
- Explain what's happening at each step
- Highlight the security features being demonstrated

## Additional Resources

- **PRESENTATION.md:** Full presentation content
- **PRESENTATION_OUTLINE.md:** Detailed outline with notes
- **DEMO_GUIDE.md:** Guide for running demos
- **README.md:** Project documentation
- **BLOCKCHAIN_SECURITY_README.md:** Security documentation


