// WARNING
//
// This file has been generated automatically by Xamarin Studio from the outlets and
// actions declared in your storyboard file.
// Manual changes to this file will not be maintained.
//

using System.CodeDom.Compiler;
using Foundation;
using UIKit;

namespace AdaliOSSample
{
	[Register ("MsaliOSTestAppViewController")]
	partial class MsaliOSTestAppViewController
	{
		[Outlet]
		[GeneratedCode ("iOS Designer", "1.0")]
		UITextView ReportLabel { get; set; }

		[Action ("UIButton11_TouchUpInside:")]
		[GeneratedCode ("iOS Designer", "1.0")]
		partial void UIButton11_TouchUpInside (UIButton sender);

		[Action ("UIButton16_TouchUpInside:")]
		[GeneratedCode ("iOS Designer", "1.0")]
		partial void UIButton16_TouchUpInside (UIButton sender);

		[Action ("UIButton30_TouchUpInside:")]
		[GeneratedCode ("iOS Designer", "1.0")]
		partial void UIButton30_TouchUpInside (UIButton sender);

		void ReleaseDesignerOutlets ()
		{
			if (ReportLabel != null) {
				ReportLabel.Dispose ();
				ReportLabel = null;
			}
		}
	}
}
