//----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//----------------------------------------------------------------------

namespace Microsoft.Identity.Client
{
    /// <summary>
    /// Additional parameters used in acquiring user's authorization
    /// </summary>
    public class PlatformParameters : IPlatformParameters
    {
        /// <summary>
        /// 
        /// </summary>
        public PlatformParameters():this(null)
        {
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="promptBehavior"></param>
        /// <param name="ownerWindow"></param>
        public PlatformParameters(object ownerWindow)
        {
            this.OwnerWindow = ownerWindow;
        }

        /// <summary>
        /// Gets the owner of the browser dialog which pops up for receiving user credentials. It can be null.
        /// </summary>
        public object OwnerWindow { get; private set; }
        
    }
}